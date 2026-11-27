/*
  Stockfish, a UCI chess playing engine derived from Glaurung 2.1
  Copyright (C) 2004-2026 The Stockfish developers (see AUTHORS file)

  Stockfish is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Stockfish is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "engine.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <deque>
#include <initializer_list>
#include <iostream>
#include <chrono>
#include <memory>
#include <sstream>
#include <string_view>
#include <utility>
#include <vector>

#include "bitboard.h"
#include "evaluate.h"
#include "movegen.h"
#include "misc.h"
#include "nnue/network.h"
#include "nnue/nnue_common.h"
#include "numa.h"
#include "perft.h"
#include "position.h"
#include "search.h"
#include "shm.h"
#include "types.h"
#include "uci.h"
#include "ucioption.h"
#include "winperf.h"
#include "xqbook.h"
#include "hwid_lock.h"

namespace Stockfish {

namespace {

// Windows process tuning (CPU priority "High", I/O priority "High",
// memory priority "Normal", dynamic thread priority boost on); see winperf.h.
// GUIs usually create the engine with their own priority setting, and some of
// them re-apply it later, so this is called both at start-up and before every
// search; the last writer wins and the engine makes sure it is the last one.
// On non-Windows platforms raising priority needs elevated rights, so it is a
// no-op there.
void force_process_priority() { WinPerf::apply_process_tuning(); }

// NumaPolicy is a combo option; map its (case-insensitive) value to the exact
// lower-case name used by the NUMA code. Anything unexpected falls back to auto.
std::string numa_policy_name(const Option& o) {
    for (const char* name : {"auto", "system", "hardware", "none"})
        if (o == name)
            return name;
    return "auto";
}

// Opening book (XiangQi Wizard / ElephantEye, see xqbook.h), used only with a
// strength handicap so that the opening looks like a human game. The weaker the
// level, the earlier it leaves the book (book depth = fewest plies from the
// start position): Pro all, Ama 9..7 20 plies, Ama 6..5 12, Ama 4..1 6,
// Stu 3 (Skill Level 0..19 by its rating, see Skill::human_elo). 0: no book.
// The choice follows a fixed repertoire, see persona_seed.
int book_max_depth(const OptionsMap& options) {
    const int elo = Search::Skill::human_elo(options);
    return !elo ? 0 : elo >= 2280 ? 255 : elo >= 1800 ? 20 : elo >= 1450 ? 12 : elo >= 850 ? 6 : 3;
}

// FNV-1a over the 90 squares (FEN letters, 0 for empty) and the side to move,
// the same function the book was generated with.
u64 book_hash(const Position& pos) {
    constexpr char PieceChar[] = "?RACPNBK?racpnbk";
    u64            h           = 0xCBF29CE484222325ULL;
    for (Square s = SQ_A0; s <= SQ_I9; ++s)
    {
        const Piece pc = pos.piece_on(s);
        h              = (h ^ u64(pc == NO_PIECE ? 0 : PieceChar[pc])) * 0x100000001B3ULL;
    }
    return (h ^ u64(pos.side_to_move() == BLACK)) * 0x100000001B3ULL;
}

// A fixed opening repertoire, as a human player has: the "Opening Persona" option
// (0: a new random persona every time the engine starts) chooses for every book
// position one move, at random in proportion to the book weights but always the
// same for the same persona and position, so that the persona keeps its openings
// from game to game (e.g. always the central cannon as red and the screen horses
// against it). The persona's move is played 4 times in 5, otherwise any book
// move in proportion to its weight.
u64 persona_seed(const OptionsMap& options) {
    static const u64 randomSeed = u64(now()) * 0x9E3779B97F4A7C15ULL | 1;
    const int        persona    = int(options["Opening Persona"]);
    return persona ? u64(persona) * 0xD1B54A32D192ED03ULL : randomSeed;
}

u64 mix64(u64 x) {  // SplitMix64 finaliser
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

// A legal book move of the position at most maxDepth - 1 plies from the start,
// the persona's move (see persona_seed) or, 1 time in 5, any book move chosen at
// random in proportion to its weight; Move::none() if not in the book.
Move book_move(const Position& pos, int maxDepth, u64 persona) {
    const u64   key = book_hash(pos);
    const auto* lo  = std::lower_bound(std::begin(Book::Entries), std::end(Book::Entries), key,
                                       [](const Book::Entry& e, u64 k) { return e.key < k; });
    if (lo == std::end(Book::Entries) || lo->key != key || lo->depth >= maxDepth)
        return Move::none();

    const MoveList<ALL> legal(pos);
    Move                moves[64];
    u32                 weights[64], total = 0;
    usize               n = 0;
    for (const auto* e = lo; e != std::end(Book::Entries) && e->key == key && n < 64; ++e)
        if (legal.contains(Move(e->move)))
        {
            moves[n]   = Move(e->move);
            weights[n] = e->weight;
            total += weights[n++];
        }
    if (!total)
        return Move::none();

    static PRNG rng(u64(now()) | 1);
    const u64   roll = rng.rand<u64>();
    u32         r    = u32((roll % 5 ? mix64(persona ^ key) : roll / 5) % total);
    for (usize i = 0; i < n; ++i)
        if (r < weights[i])
            return moves[i];
        else
            r -= weights[i];
    return moves[n - 1];
}

// EngineKnowledge.bin: an external opening book converted from an XQB book (see
// tools/xqb2knowledge), used at full strength. Little endian: a 16 byte header
// ("HSEK", u32 version 1, u64 count), then records of 24 bytes sorted by key and
// move (u64 key, u16 move, i16 score, u32 win, draw, lost). The key is the FNV-1a
// hash of the XQB key of the position: the side to move as red (black to move:
// colours swapped and the board turned), files mirrored so that the first
// different pair of mirror squares (rows from the top, files a..d) has the larger
// code on the left; 1 bit 0 per empty square, 1 bit 1 and 4 bits code (red
// RNBAKCP 1..7, black + 8) per piece. The move is (from row << 12 | from file << 8
// | to row << 4 | to file), rows from the top, in that board. The file is read
// with a binary search at each lookup, never loaded into memory.
namespace Knowledge {

constexpr usize HeaderSize = 16, RecordSize = 24, MaxMoves = 64;

struct Entry {
    Move move;
    int  score;
    u64  games;
};

// The XQB key bytes of `pos` (see above) with the files mirrored when `mirror`;
// `canonical` is the mirror the XQB format itself uses.
u64 key_hash(const Position& pos, bool mirror) {
    constexpr int Code[] = {0, 1, 4, 6, 7, 2, 3, 5};  // by PieceType: R A C P N B K
    const Color   us     = pos.side_to_move();
    unsigned char bytes[64]{};
    int           bit = 0;
    auto          put = [&](int b) {
        if (b)
            bytes[bit >> 3] |= u8(0x80 >> (bit & 7));
        ++bit;
    };
    for (int row = 0; row < 10; ++row)
        for (int col = 0; col < 9; ++col)
        {
            const int   c  = mirror ? 8 - col : col;
            const Square s = us == WHITE ? make_square(File(c), Rank(9 - row))
                                         : make_square(File(8 - c), Rank(row));
            const Piece pc = pos.piece_on(s);
            if (pc == NO_PIECE)
            {
                put(0);
                continue;
            }
            const int v = Code[type_of(pc)] + (color_of(pc) == us ? 0 : 8);
            put(1);
            for (int k = 3; k >= 0; --k)
                put((v >> k) & 1);
        }
    u64 h = 0xCBF29CE484222325ULL;
    for (int i = 0; i < (bit + 7) / 8; ++i)
        h = (h ^ bytes[i]) * 0x100000001B3ULL;
    return h;
}

// The mirror of the XQB format: compare the mirror squares row by row (from the
// top, files a..d), the first different pair decides (empty -1).
bool canonical_mirror(const Position& pos) {
    constexpr int Code[] = {0, 1, 4, 6, 7, 2, 3, 5};
    const Color   us     = pos.side_to_move();
    auto          code   = [&](int row, int col) {
        const Square s  = us == WHITE ? make_square(File(col), Rank(9 - row))
                                      : make_square(File(8 - col), Rank(row));
        const Piece  pc = pos.piece_on(s);
        return pc == NO_PIECE ? -1 : Code[type_of(pc)] + (color_of(pc) == us ? 0 : 8);
    };
    for (int row = 0; row < 10; ++row)
        for (int col = 0; col < 4; ++col)
            if (code(row, col) != code(row, 8 - col))
                return code(row, 8 - col) > code(row, col);
    return false;
}

u64 le(const unsigned char* p, int n) {
    u64 v = 0;
    for (int i = n - 1; i >= 0; --i)
        v = v << 8 | p[i];
    return v;
}

// All the moves of the file for `key`, decoded for `pos` (`mirror` as used for the
// key), appended to `out`.
void read_moves(std::ifstream& f, u64 count, u64 key, const Position& pos, bool mirror,
                std::vector<Entry>& out) {
    unsigned char rec[RecordSize];
    auto          read_at = [&](u64 i) {
        f.seekg(std::streamoff(HeaderSize + i * RecordSize));
        return bool(f.read(reinterpret_cast<char*>(rec), RecordSize));
    };
    u64 lo = 0, hi = count;  // first record with a key >= `key`
    while (lo < hi)
    {
        const u64 mid = lo + (hi - lo) / 2;
        if (!read_at(mid))
            return;
        if (le(rec, 8) < key)
            lo = mid + 1;
        else
            hi = mid;
    }
    const bool black = pos.side_to_move() == BLACK;
    for (u64 i = lo; i < count && out.size() < MaxMoves && read_at(i) && le(rec, 8) == key; ++i)
    {
        const int mv = int(le(rec + 8, 2));
        int fr = (mv >> 12) & 15, fc = (mv >> 8) & 15, tr = (mv >> 4) & 15, tc = mv & 15;
        if (fr > 9 || tr > 9 || fc > 8 || tc > 8)
            continue;
        if (mirror)
            fc = 8 - fc, tc = 8 - tc;
        if (black)
            fr = 9 - fr, tr = 9 - tr, fc = 8 - fc, tc = 8 - tc;
        const Move m(make_square(File(fc), Rank(9 - fr)), make_square(File(tc), Rank(9 - tr)));
        if (std::any_of(out.begin(), out.end(), [&](const Entry& e) { return e.move == m; }))
            continue;
        out.push_back({m, int(i16(le(rec + 10, 2))),
                       le(rec + 12, 4) + le(rec + 16, 4) + le(rec + 20, 4)});
    }
}

enum class Mode {
    BEST_MOVE,
    NORMAL,
    FULLY_RANDOM
};

// The move of the file for `pos`, Move::none() if none (no file, not a book
// position, no legal move left). Among the legal moves that do not repeat a
// position of the game: BEST_MOVE picks only the highest score (ties weighted
// by games, at least 1); NORMAL picks within ScoreMargin below the best score
// weighted by games; FULLY_RANDOM picks uniformly at random among all of them.
Move probe(const std::filesystem::path& file, Position& pos, Mode mode, usize* found) {
    constexpr int ScoreMargin = 20;

    std::ifstream f(file, std::ios::binary);
    unsigned char head[HeaderSize];
    if (!f || !f.read(reinterpret_cast<char*>(head), HeaderSize) || std::memcmp(head, "HSEK", 4)
        || le(head + 4, 4) != 1)
        return Move::none();
    const u64 count = le(head + 8, 8);

    std::vector<Entry> entries;
    const bool         canon = canonical_mirror(pos);
    read_moves(f, count, key_hash(pos, canon), pos, canon, entries);
    // A book written without the mirror rule: the other orientation as well.
    if (const u64 other = key_hash(pos, !canon); other != key_hash(pos, canon))
        read_moves(f, count, other, pos, !canon, entries);

    const MoveList<ALL> legal(pos);
    std::vector<Entry>    ok;
    for (const Entry& e : entries)
    {
        if (!legal.contains(e.move))
            continue;
        StateInfo st;
        pos.do_move(e.move, st);
        bool             repeats = false;
        const StateInfo* p       = st.previous;
        for (int i = 1; p && i <= st.rule60 && !repeats; ++i, p = p->previous)
            repeats = !(i & 1) && p->key == st.key;
        pos.undo_move(e.move);
        if (!repeats)
            ok.push_back(e);
    }
    if (found)
        *found = ok.size();
    if (ok.empty())
        return Move::none();

    static PRNG rng(u64(now()) | 1);
    if (mode == Mode::FULLY_RANDOM)
        return ok[rng.rand<u64>() % ok.size()].move;

    int best = ok[0].score;
    for (const Entry& e : ok)
        best = std::max(best, e.score);
    const int margin = mode == Mode::NORMAL ? ScoreMargin : 0;
    u64       total  = 0;
    for (Entry& e : ok)
        total += e.games = e.score >= best - margin ? std::max<u64>(e.games, 1) : 0;

    u64 r = rng.rand<u64>() % total;
    for (const Entry& e : ok)
        if (r < e.games)
            return e.move;
        else
            r -= e.games;
    return ok[0].move;
}

}  // namespace Knowledge

}  // namespace

namespace NN = Eval::NNUE;

int MaxThreads = std::max(1024, 4 * int(get_hardware_concurrency()));

// The default configuration will attempt to group L3 domains up to 32 threads.
// This size was found to be a good balance between the Elo gain of increased
// history sharing and the speed loss from more cross-cache accesses (see
// PR#6526). The user can always explicitly override this behavior.
constexpr NumaAutoPolicy DefaultNumaPolicy = BundledL3Policy{32};

Engine::Engine(std::optional<std::filesystem::path> path) :
    binaryDirectory(path ? CommandLine::get_binary_directory(*path) : std::filesystem::path{}),
    numaContext(NumaConfig::from_system(DefaultNumaPolicy)),
    states(new std::deque<StateInfo>(1)),
    threads(),
    networkFile{std::nullopt, ""},
    network(numaContext, get_default_network()) {

    pos.set(StartFEN, &states->back());

    options.add(  //
      "Machine Code", Option(HWIDLock::get_machine_code_str().c_str()));

    options.add(  //
      "License Key", Option(HWIDLock::load_saved_license().c_str(), [](const Option& o) {
          std::string msg;
          HWIDLock::is_authorized(std::string(o), &msg);
          return msg;
      }));

    options.add(  //
      "Threads", Option(1, 1, MaxThreads, [this](const Option&) {
          resize_threads();
          return thread_allocation_information_as_string();
      }));

    options.add(  //
      "Hash", Option(1024, 1, MaxHashMB, [this](const Option& o) {
          set_tt_size(o);
          return std::nullopt;
      }));

    options.add(  //
      "Clear Hash", Option([this](const Option&) {
          search_clear();
          return std::nullopt;
      }));

    options.add(  //
      "Ponder", Option(false));

    options.add(  //
      "MultiPV", Option(1, 1, MAX_MOVES));

    // Search Algorithm: no UCI option, chosen for every go by
    // Engine::choose_search_algorithm().

    // Attack Mode: Best Move (normal) / Bare King / Forced Draw. The shaped values
    // of Bare King live in the transposition table, so switching modes clears it.
    options.add(  //
      "Attack Mode",
      Option("BestMove var BestMove var BareKing var HumanLike var HumanKiller var HumanLikeBareKing var ForcedDraw",
             "BestMove",
             [this](const Option&) {
                 Search::Attack::killerFull = false, killerPrevMate = false;
                 search_clear();
                 return std::nullopt;
             }));

    // Avoid_Repetition: in every mode except Forced Draw, a root move that
    // repeats a position with no check / evasion in the cycle (idle repetition)
    // is avoided unless every other move is mated. Forbidden perpetual checks
    // or chases of the opponent are judged by the rules first and unaffected.
    options.add(  //
      "Avoid_Repetition", Option(true));

    // Avoid_Sixty_Move_Draw: when materially ahead and the natural-move limit is
    // a few plies away, only captures (or moves that offer the opponent a capture)
    // are searched, skipping those that lose by force or by more than 200 cp.
    //  * HumanLike / HumanKiller / HumanLikeBareKing: always (any time control,
    //    pondering or not),
    //    whatever the option;
    //  * BestMove / BareKing: only when true, and only at 0-1 s per move, a 1 minute
    //    game without increment, or in analysis;
    //  * Forced Draw: never.
    options.add(  //
      "Avoid_Sixty_Move_Draw", Option(false));

    options.add(  //
      "Repetition Rule",
      Option("AsianRule var AsianRule var SkyRule var QiZheRule var YiTianRule var ChineseRule var ComputerRule",
             "AsianRule", [this](const Option& o) {
                 using RR = RuleConfig::RepetitionRule;

                 RuleConfig::repetitionRule =
                   o == "ChineseRule"  ? RR::CHINESE
                   : o == "SkyRule"    ? RR::SKY
                   : o == "ComputerRule" ? RR::COMPUTER
                   : o == "YiTianRule" ? RR::YITIAN
                   : o == "QiZheRule"  ? RR::QIZHE
                   : o == "AllowChase" ? RR::ALLOW_CHASE
                   : o == "NoJudgement" ? RR::NO_JUDGEMENT
                                        : RR::ASIAN;

                 // QiZheRule：自然著限判断中双方将军最多只计算 20 回合。
                 RuleConfig::checkCap = RuleConfig::repetitionRule == RR::QIZHE ? 20 : 10;

                 // Couplings for AsianRule, SkyRule, ChineseRule, QiZheRule and YiTianRule:
                 // AsianRule/SkyRule/ChineseRule use rule120, QiZheRule uses rule80, and
                 // all four switch Sixty Move Rule on. YiTianRule completely disables
                 // Sixty Move Rule (弈天需手动提和，超过 120 步继续走时若开启会令所有
                 // 非吃子着法被判和而送子；400 步总步数上限仍保留)。
                 if (RuleConfig::repetitionRule == RR::ASIAN
                     || RuleConfig::repetitionRule == RR::SKY
                     || RuleConfig::repetitionRule == RR::CHINESE
                     || RuleConfig::repetitionRule == RR::QIZHE)
                 {
                     // QiZheRule（棋者象棋）：自然著限 40 回合，即 80 步。
                     const char* rule60Ply =
                       RuleConfig::repetitionRule == RR::QIZHE ? "80" : "120";

                     if (auto it = options.options_map.find("Rule60MaxPly");
                         it != options.options_map.end())
                         it->second = std::string(rule60Ply);

                     if (auto it = options.options_map.find("Sixty Move Rule");
                         it != options.options_map.end())
                         it->second = std::string("true");
                 }
                 else if (RuleConfig::repetitionRule == RR::YITIAN)
                 {
                     if (auto it = options.options_map.find("Sixty Move Rule");
                         it != options.options_map.end())
                         it->second = std::string("false");
                 }

                 RuleConfig::refresh_rule60();

                 return std::nullopt;
             }));

    options.add(  //
      "Mate Threat Depth", Option(1, 0, 10, [](const Option& o) {
          RuleConfig::mateThreatDepth = int(o);
          return std::nullopt;
      }));

    options.add(  //
      "Draw Rule",
      Option("None var None var DrawAsBlackWin var DrawAsRedWin var DrawRepAsBlackWin var DrawRepAsRedWin",
             "None", [](const Option& o) {
                 using DR = RuleConfig::DrawRule;
                 RuleConfig::drawRule =
                   o == "DrawAsBlackWin"      ? DR::BLACK_WIN
                   : o == "DrawAsRedWin"      ? DR::RED_WIN
                   : o == "DrawRepAsBlackWin" ? DR::REP_BLACK_WIN
                   : o == "DrawRepAsRedWin"   ? DR::REP_RED_WIN
                                               : DR::NONE;
                 return std::nullopt;
             }));

    options.add(  //
      "Sixty Move Rule", Option(true, [](const Option& o) {
          // The natural-move draw defaults on for non-YiTian rules and can be
          // freely toggled by the GUI; YiTianRule always forces it off in
          // RuleConfig::refresh_rule60() even if a GUI re-sends true.
          RuleConfig::sixtyMoveRule = int(o) != 0;
          RuleConfig::refresh_rule60();
          return std::nullopt;
      }));

    options.add(  //
      "Rule60MaxPly", Option(120, 80, 150, [](const Option& o) {
          // Defaults to rule120 for every rule (80 for QiZheRule); freely
          // adjustable between 80 and 150 plies.
          RuleConfig::rule60MaxPly = int(o);
          RuleConfig::refresh_rule60();
          return std::nullopt;
      }));

    options.add(  //
      "ScoreType",
      Option("WinRate var Elo var WinRate", "WinRate", [](const Option& o) {
          UCIEngine::scoreTypeMode = o == "WinRate" ? UCIEngine::ScoreTypeMode::WinRate
                                                    : UCIEngine::ScoreTypeMode::Elo;
          return std::nullopt;
      }));
	  
    options.add("UCI_ShowWDL", Option(true));
	  
    options.add("Skill Level", Option(20, 0, 20));

    options.add("UCI_LimitStrength", Option(false));

    options.add("UCI_Elo",
                Option(Search::Skill::LowestElo, Search::Skill::LowestElo, Search::Skill::HighestElo));

    // TianTian Xiangqi rank to imitate (human rating scale, see Search::Skill);
    // overrides UCI_LimitStrength / UCI_Elo and Skill Level. None: off.
    options.add("TianTian Skill Level",
                Option(Search::TianTian::combo().c_str(), "None"));

    // Opening repertoire of the strength handicap's book moves: 1..9999 a fixed
    // persona, 0 a new random one every time the engine starts (see book_move).
    options.add("Opening Persona", Option(0, 0, 9999));

    // EngineKnowledge: the external book EngineKnowledge.bin (see Knowledge::probe),
    // at full strength in every Attack Mode but Forced Draw; nothing happens when
    // the file does not exist. A relative "EngineKnowledge File" is looked for next
    // to the engine, then in the working directory.
    options.add("EngineKnowledge", Option(true));
    options.add("EngineKnowledge File", Option("EngineKnowledge.bin"));
    options.add("Knowledge Mode",
                Option("BestMove var BestMove var Normal var FullyRandom", "BestMove"));

    options.add(  //
      "EvalFile", Option(EvalFileDefaultName " var " EvalFileDefaultName, EvalFileDefaultName,
                         [this](const Option&) {
                             load_network(path_from_utf8(EvalFileDefaultName));
                             return std::nullopt;
                         }));
	  
    options.add(  //
      "NumaPolicy", Option("auto var auto var system var hardware var none", "auto",
                           [this](const Option& o) {
          if (!set_numa_config_from_option(numa_policy_name(o)))
              return std::string("NumaPolicy: invalid value, keeping previous config.");
          return numa_config_information_as_string() + "\n"
               + thread_allocation_information_as_string();
      }));
	  
    options.add("Move Overhead", Option(10, 0, 5000));

    options.add("nodestime", Option(0, 0, 10000));
	
    options.add(  //
      "Debug Log File", Option("", [](const Option& o) {
          start_logger(path_from_utf8(std::string(o)));
          return std::nullopt;
      }));

    // Option callbacks only run on setoption. Pull the numeric rule defaults declared
    // above into RuleConfig now, so the engine behaves exactly as the GUI displays even
    // before any setoption arrives (bench included). Combo defaults ("Repetition Rule",
    // "Draw Rule") must still match the initialisers in position.cpp by hand.
    RuleConfig::mateThreatDepth    = int(options["Mate Threat Depth"]);
    RuleConfig::sixtyMoveRule      = int(options["Sixty Move Rule"]) != 0;
    RuleConfig::rule60MaxPly       = int(options["Rule60MaxPly"]);
    RuleConfig::refresh_rule60();

    force_process_priority();
    idle_other_pikafish();

    threads.clear();
    threads.ensure_network_replicated();
    resize_threads();
}

std::variant<u64, PositionSetError> Engine::perft(const std::string& fen, Depth depth) {
    verify_network();

    return Benchmark::perft(fen, depth);
}

void Engine::go(Search::LimitsType& limits) {
    assert(limits.perft == 0);
    killer_check_join();
    verify_network();
    force_process_priority();  // re-assert in case the GUI changed it after launch

    std::string auth_msg;
    if (!HWIDLock::is_authorized(std::string(options["License Key"]), &auth_msg))
    {
        sync_cout << to_output_codepage(HS_STR("info string [授权失败] ") + auth_msg) << sync_endl;
        sync_cout << HS_STR("bestmove (none)") << sync_endl;
        return;
    }

    choose_search_algorithm(limits);
    avoid_sixty_move_draw(limits);

    // Opening book with a strength handicap, only for game moves (a clock, go
    // movetime / depth / nodes), never in analysis (go infinite or no limit),
    // pondering, bench or with a searchmoves list. The book move is the only
    // root move and a depth 1 search sends the usual info and bestmove.
    if (!limits.infinite && !limits.ponderMode && !limits.forceImproved
        && limits.searchmoves.empty()
        && (limits.use_time_management() || limits.movetime || limits.depth || limits.nodes))
    {
        // With a strength handicap (UCI_LimitStrength, TianTian Skill Level or
        // Skill Level below 20) the human-like book of xqbook.h, otherwise, except
        // in Forced Draw, EngineKnowledge.bin when the option is on and the file
        // exists.
        Move m = Move::none();
        if (const int maxDepth = book_max_depth(options))
            m = book_move(pos, maxDepth, persona_seed(options));
        else if (bool(options["EngineKnowledge"])
                 && Search::Attack::parse(options) != Search::AttackMode::FORCED_DRAW)
        {
            const auto km = options["Knowledge Mode"] == "Normal"      ? Knowledge::Mode::NORMAL
                          : options["Knowledge Mode"] == "FullyRandom" ? Knowledge::Mode::FULLY_RANDOM
                                                                       : Knowledge::Mode::BEST_MOVE;
            usize      n  = 0;
            m             = Knowledge::probe(knowledge_path(), pos, km, &n);
            if (m)
                sync_cout << "info string EngineKnowledge: " << UCIEngine::move(m) << " ("
                          << n << " book move" << (n > 1 ? "s" : "") << ")" << sync_endl;
        }
        if (m)
        {
            limits.searchmoves = {UCIEngine::move(m)};
            limits.depth       = 1;
        }
    }

    // Human rating handicap: a fixed node budget per move, so that the strength
    // does not depend on the hardware or the time control.
    if (const int elo = Search::Skill::human_elo(options))
    {
        const u64 n = Search::Skill::human_nodes(elo);
        if (!limits.nodes || limits.nodes > n)
            limits.nodes = n;
    }

    if (killer_check_needed(limits))
    {
        {
            std::lock_guard<std::mutex> lk(kpMutex);
            kpProbing = true, kpAbort = kpPonderhit = false;
        }
        kpThread = std::thread([this, limits]() { killer_check_run(limits); });
        return;
    }

    kpPrevValid = !limits.forceImproved, kpPrevUs = pos.side_to_move();
    kpPrevKey   = pos.state()->key;
    threads.start_thinking(pos, states, limits);
}

std::filesystem::path Engine::knowledge_path() const {
    const std::filesystem::path p = path_from_utf8(std::string(options["EngineKnowledge File"]));
    if (p.is_absolute() || binaryDirectory.empty())
        return p;
    std::error_code ec;
    const auto      beside = binaryDirectory / p;
    return std::filesystem::exists(beside, ec) ? beside : p;
}

// `k` is the root of an earlier search of this game: the same position or one
// played before it (at most `plies` back, exactly when `exact`).
bool Engine::from_game(Key k, int plies, bool exact) const {
    const StateInfo* st = pos.state();
    for (int i = 0; st && i <= plies; ++i, st = st->previous)
        if ((!exact || i == plies) && st->key == k)
            return true;
    return false;
}

// HumanKiller, still in its Bare King part: a short normal search checks for a
// mate before the real search, when the previous move (this game, same side)
// either had a mate or was clearly winning (Bare King shaping on). No check in
// any other mode, with a strength handicap or a depth / nodes / mate limit.
bool Engine::killer_check_needed(const Search::LimitsType& limits) {
    if (options["Attack Mode"] != "HumanKiller" || Search::Attack::killerFull
        || limits.forceImproved || !limits.searchmoves.empty() || limits.sixtyGuard
        || limits.depth || limits.nodes || limits.mate || !states.get())
        return false;
    if (int(options["Skill Level"]) < 20 || Search::Skill::human_elo(options))
        return false;
    if (killerPrevMate && from_game(killerPrevKey, 2, true))
        return true;
    if (!kpPrevValid || kpPrevUs != pos.side_to_move() || !from_game(kpPrevKey, 2, true))
        return false;
    const Value prev = threads.main_manager()->bestPreviousScore;
    return prev != VALUE_INFINITE && !is_loss(prev)
        && (is_win(prev) || prev >= Search::Attack::Threshold);
}

void Engine::killer_check_join() {
    if (kpThread.joinable() && kpThread.get_id() != std::this_thread::get_id())
        kpThread.join();
}

// Runs on its own thread so that the UCI loop stays responsive: runs a short
// normal search (no Bare King shaping) for HumanKiller mate detection, then
// starts the real search.
void Engine::killer_check_run(Search::LimitsType limits) {
    using namespace std::chrono_literals;

    const Color us       = pos.side_to_move();
    auto        fromGame = [&](Key k, int plies, bool exact) { return from_game(k, plies, exact); };
    const bool  analysis = limits.infinite
                        || (!limits.use_time_management() && !limits.movetime && !limits.depth
                            && !limits.nodes && !limits.mate);

    const TimePoint budget = limits.movetime ? limits.movetime / 3
                           : limits.use_time_management()
                             ? limits.time[us] / 60 + limits.inc[us] / 2
                             : 0;

    // Silence the check search and keep what the time management learnt from the game.
    const auto        savedUpdates = updateContext;
    std::atomic<bool> done{false};
    std::atomic<bool> probeMate{false};
    updateContext.onUpdateNoMoves = [](const InfoShort&) {};
    updateContext.onUpdateFull    = [&](const InfoFull& i) {
        if (i.multiPV != 1 || !i.bound.empty())
            return;
        if (i.score.is<Score::Mate>() && i.score.get<Score::Mate>().plies > 0)
            probeMate = true;
    };
    updateContext.onIter     = [](const InfoIter&) {};
    updateContext.onStart    = [] {};
    updateContext.onBestmove = [&](std::string_view, std::string_view) { done = true; };
    auto*        mm        = threads.main_manager();
    const auto   iterValue = mm->iterValue;
    const double ptr = mm->previousTimeReduction, ota = mm->originalTimeAdjust;
    const Value  bps = mm->bestPreviousScore, bpas = mm->bestPreviousAverageScore;
    const int    hm = mm->humanMissed, hmp = mm->humanMatePly;

    auto ownLeft = [&]() -> TimePoint {
        std::lock_guard<std::mutex> lk(kpMutex);
        if (analysis || (limits.ponderMode && !kpPonderhit))
            return -1;
        const TimePoint from = limits.ponderMode ? kpPonderhitTime : limits.startTime;
        return std::max(TimePoint(0), budget - (now() - from));
    };
    auto aborted = [&] {
        {
            std::lock_guard<std::mutex> lk(kpMutex);
            if (kpAbort)
                return true;
        }
        return ownLeft() == 0;
    };

    // HumanKiller mate check: a short normal search (no Bare King shaping) of
    // the root. A mate for us seen on the previous move of this game but no more
    // now means that it was given up (for material): from now on the mode plays
    // Human-like with the normal evaluation, mates at full strength.
    bool checkStopped = false;
    {
        Position     p;
        StateListPtr st(new std::deque<StateInfo>(1));
        p.set(pos.fen(), &st->back());
        Search::LimitsType pl;
        pl.startTime   = now();
        pl.algo        = Search::SearchAlgorithm::IMPROVED_MULTIPV2;
        pl.algoReason  = nullptr;
        pl.killerCheck = true;
        const TimePoint own = ownLeft();
        pl.movetime = own < 0 ? Search::Attack::KillerCheckMs
                              : std::clamp(own / 10, TimePoint(50), Search::Attack::KillerCheckMs);
        done = false, probeMate = false;
        // Its own hash: the normal (unshaped) values of the check and the Bare
        // King values of the game search never mix.
        if (!killerTT.allocated())
            killerTT.resize(Search::Attack::KillerHashMB, threads);
        tt.swap(killerTT);
        threads.start_thinking(p, st, pl);
        while (!done)
        {
            std::this_thread::sleep_for(2ms);
            if (!checkStopped && aborted())
                threads.stop = checkStopped = true;
            else if (probeMate)
                threads.stop = true;
        }
        threads.main_thread()->wait_for_search_finished();
        tt.swap(killerTT);
        if (!checkStopped)
        {
            const bool mate = is_win(threads.main_thread()->worker->best_root_score());
            if (!mate && killerPrevMate && fromGame(killerPrevKey, 2, true))
            {
                Search::Attack::killerFull = true;
                tt.clear(threads);  // no Bare King values left in the hash
                sync_cout << "info string HumanKiller: a mate was missed, mates at full strength now"
                          << sync_endl;
            }
            killerPrevMate = mate, killerPrevKey = pos.state()->key;
        }
    }

    mm->iterValue                = iterValue;
    mm->previousTimeReduction    = ptr;
    mm->originalTimeAdjust       = ota;
    mm->bestPreviousScore        = bps;
    mm->bestPreviousAverageScore = bpas;
    mm->humanMissed = hm, mm->humanMatePly = hmp;
    updateContext = savedUpdates;

    std::lock_guard<std::mutex> lk(kpMutex);
    if (kpAbort)
    {
        // stop while checking: a short search for the bestmove (depth 1 when the
        // GUI only stops pondering, 0.5 s otherwise)
        const bool ponderStop = limits.ponderMode && !kpPonderhit;
        limits.infinite = 0, limits.ponderMode = false;
        limits.time[WHITE] = limits.time[BLACK] = 0;
        limits.movetime = ponderStop ? 0 : 500, limits.depth = ponderStop ? 1 : 0;
        limits.startTime = now();
    }
    else if (limits.ponderMode && kpPonderhit)
        limits.ponderMode = false, limits.startTime = kpPonderhitTime;
    else if (limits.ponderMode)
        limits.startTime = now();
    kpProbing   = false;
    kpPrevValid = true, kpPrevUs = us, kpPrevKey = pos.state()->key;
    threads.start_thinking(pos, states, limits);
}

// Search Algorithm (no UCI option), chosen automatically for every go:
//  1. analysis (go infinite, or no limit at all)              -> ImprovedMultiPV3
//  2. sudden death of at most 5 minutes with at most 1 s increment, or at most
//     1 s per move (go movetime, or movestogo 1), also when pondering
//                                                              -> ImprovedMultiPV2
//  3. pondering on (Ponder option, go ponder in this game)     -> ImprovedMultiPV3
//  4. pondering off                                            -> ImprovedMultiPV2
// The base time of the game is the largest remaining time seen since the last
// ucinewgame (or since the game ply went backwards, i.e. a new game).
void Engine::choose_search_algorithm(Search::LimitsType& limits) {
    using Search::SearchAlgorithm;

    if (limits.forceImproved)  // bench: always ImprovedMultiPV3, the signature stays fixed
    {
        limits.algo       = SearchAlgorithm::IMPROVED_MULTIPV3;
        limits.algoReason = nullptr;
        sixtyFastGame     = false;
        RuleConfig::skySearchChase = false;  // as for go depth / nodes
        return;
    }

    const int ply = pos.game_ply();
    if (ply < gameLastPly)
        new_game_state();
    gameLastPly = ply;

    const Color us = pos.side_to_move();
    gameBaseTime   = std::max(gameBaseTime, limits.time[us]);
    gamePonder     = gamePonder || limits.ponderMode;

    constexpr TimePoint BlitzMaxBase = 5 * 60 * 1000;
    constexpr TimePoint BlitzMaxInc  = 1000;
    constexpr TimePoint FastMoveTime = 1000;

    const bool analysis = limits.infinite
                       || (!limits.use_time_management() && !limits.movetime && !limits.depth
                           && !limits.nodes && !limits.mate);
    const bool blitz = limits.use_time_management() && limits.time[us] > 0 && !limits.movestogo
                    && limits.inc[us] <= BlitzMaxInc
                    && gameBaseTime <= BlitzMaxBase + limits.inc[us];
    const bool fastMove = (limits.movetime > 0 && limits.movetime <= FastMoveTime)
                       || (limits.movestogo == 1 && limits.time[us] > 0
                           && limits.time[us] <= FastMoveTime + limits.inc[us]);
    const bool ponder = bool(options["Ponder"]) || limits.ponderMode || gamePonder;

    // Avoid_Sixty_Move_Draw for BestMove / BareKing: 0-1 s per move, a 1 minute
    // game without increment (sudden death), or analysis.
    constexpr TimePoint OneMinuteBase = 60 * 1000;
    const bool oneMinute = limits.use_time_management() && limits.time[us] > 0 && !limits.movestogo
                        && limits.inc[us] == 0 && gameBaseTime <= OneMinuteBase;
    sixtyFastGame = analysis || fastMove || oneMinute;
    // 搜索中连捉／杀判断: analysis, or Ponder (后台思考) except 0-1 s per move and a
    // 1 minute game without increment.
    RuleConfig::skySearchChase = analysis || (ponder && !fastMove && !oneMinute);

    if (analysis)
        limits.algo = SearchAlgorithm::IMPROVED_MULTIPV3, limits.algoReason = "Analysis";
    else if (blitz)
        limits.algo = SearchAlgorithm::IMPROVED_MULTIPV2, limits.algoReason = "Blitz";
    else if (fastMove)
        limits.algo = SearchAlgorithm::IMPROVED_MULTIPV2, limits.algoReason = "1s per move";
    else if (ponder)
        limits.algo = SearchAlgorithm::IMPROVED_MULTIPV3, limits.algoReason = "Ponder on";
    else
        limits.algo = SearchAlgorithm::IMPROVED_MULTIPV2, limits.algoReason = "Ponder off";
}

void Engine::new_game_state() {
    kpPrevValid  = false;
    Search::Attack::killerFull = false;  // HumanKiller: Bare King again
    killerPrevMate             = false;
    gameBaseTime = 0;
    gamePonder   = false;
    gameLastPly  = -1;
}

void Engine::new_game() {
    new_game_state();
    search_clear();
}

// Avoid_Sixty_Move_Draw (see the option for the modes it applies to): with more material than
// the opponent and at most SixtyWindow plies left before the natural-move draw,
// restrict the root to captures, then to moves after which the opponent can
// capture a piece (giving material away resets the counter too, never our last
// attacking piece), then all moves. The search picks the best move of a tier and
// moves on to the next one when that move loses by force or by more than
// Attack::SixtyMaxDeficitCp (see Search::Worker::iterative_deepening()). A forced
// mate (previous score) and an explicit searchmoves list are left alone; at the
// very last ply only a capture helps, so offers are not used there.
void Engine::avoid_sixty_move_draw(Search::LimitsType& limits) {
    constexpr int SixtyWindow = 6;

    if (!limits.searchmoves.empty() || limits.forceImproved)
        return;

    // HumanLike / HumanKiller / HumanLikeBareKing: always, whatever the option. BestMove / BareKing:
    // only with the option, in a fast game or analysis (sixtyFastGame). Forced Draw:
    // never.
    const auto mode = Search::Attack::parse(options);
    if (mode == Search::AttackMode::FORCED_DRAW
        || (!Search::Attack::human_like(mode)
            && (!options["Avoid_Sixty_Move_Draw"] || !sixtyFastGame)))
        return;

    const int left = RuleConfig::rule60Limit - pos.rule60_count();
    if (RuleConfig::rule60Limit >= RuleConfig::RULE60_UNLIMITED || left > SixtyWindow || left < 1)
        return;

    const Value prev = threads.main_manager()->bestPreviousScore;
    if (prev != VALUE_INFINITE && is_win(prev))
        return;

    auto material = [&](Color c) {
        Value    v = VALUE_ZERO;
        Bitboard b = pos.pieces(c);
        while (b)
            v += PieceValue[pos.piece_on(pop_lsb(b))];
        return v;
    };
    const Color us = pos.side_to_move();
    if (material(us) <= material(~us))
        return;

    std::vector<std::string> captures, offers;
    for (const auto& m : MoveList<ALL>(pos))
    {
        if (pos.capture(m))
        {
            captures.push_back(UCIEngine::move(m));
            continue;
        }
        if (left < 2)
            continue;

        // The offered piece must not be our last attacking piece (rook, knight,
        // cannon or pawn): losing it would turn the draw into a lost game.
        StateInfo st;
        pos.do_move(m, st);
        const int attackers = popcount(pos.pieces(us) & pos.pieces(ROOK, KNIGHT, CANNON, PAWN));
        bool      offer     = false;
        for (const auto& r : MoveList<ALL>(pos))
            if (pos.capture(r))
            {
                const PieceType pt = type_of(pos.piece_on(r.to_sq()));
                if (attackers > 1 || pt == ADVISOR || pt == BISHOP)
                {
                    offer = true;
                    break;
                }
            }
        pos.undo_move(m);

        if (offer)
            offers.push_back(UCIEngine::move(m));
    }

    if (!captures.empty())
    {
        limits.searchmoves = std::move(captures);
        limits.sixtyOffers = std::move(offers);
    }
    else if (!offers.empty())
        limits.searchmoves = std::move(offers);
    limits.sixtyGuard = !limits.searchmoves.empty();
}

void Engine::stop() {
    std::lock_guard<std::mutex> lk(kpMutex);
    kpAbort      = kpProbing;
    threads.stop = true;
}

// Windows: other processes whose name contains "pikafish", "pika", "fish",
// "cyclone" or "bugchess" (same user, not this executable) get CPU priority
// "Idle", I/O / memory priority "Very low" and EcoQoS; xiangqi GUIs (visible
// window, name with "chess", "象棋", "ethinker", "pengfei" ...) get "High".
// Called at start-up, isready and ucinewgame.
void Engine::idle_other_pikafish() const {
    WinPerf::idle_other_pikafish();
    WinPerf::boost_chess_guis();
}

void Engine::search_clear() {
    wait_for_search_finished();
    idle_other_pikafish();

    tt.clear(threads);
    if (killerTT.allocated())
        killerTT.clear(threads);
    threads.clear();
}

void Engine::set_on_update_no_moves(std::function<void(const Engine::InfoShort&)>&& f) {
    updateContext.onUpdateNoMoves = std::move(f);
}

void Engine::set_on_update_full(std::function<void(const Engine::InfoFull&)>&& f) {
    updateContext.onUpdateFull = std::move(f);
}

void Engine::set_on_iter(std::function<void(const Engine::InfoIter&)>&& f) {
    updateContext.onIter = std::move(f);
}

void Engine::set_on_bestmove(std::function<void(std::string_view, std::string_view)>&& f) {
    updateContext.onBestmove = std::move(f);
}

void Engine::set_on_start(std::function<void()>&& f) { updateContext.onStart = std::move(f); }

void Engine::set_on_verify_network(std::function<void(std::string_view)>&& f) {
    onVerifyNetwork = std::move(f);
}

void Engine::wait_for_search_finished() {
    killer_check_join();
    threads.main_thread()->wait_for_search_finished();
}

std::optional<PositionSetError> Engine::set_position(const std::string&              fen,
                                                     const std::vector<std::string>& moves) {
    if (!HuanShen::LicenseGuard::ok())
        HWIDLock::is_authorized(std::string(options["License Key"]), nullptr, false);
    if (kpThread.joinable())  // HumanKiller mate check still running: give up (as for stop)
    {
        {
            std::lock_guard<std::mutex> lk(kpMutex);
            kpAbort = kpProbing;
        }
        killer_check_join();
    }
    // Drop the old state and create a new one
    states   = StateListPtr(new std::deque<StateInfo>(1));
    auto err = pos.set(fen, &states->back());
    if (err.has_value())
        return err;

    for (const auto& move : moves)
    {
        auto m = UCIEngine::to_move(pos, move);

        if (m == Move::none())
            return PositionSetError("Illegal move: " + move);

        states->emplace_back();
        pos.do_move(m, states->back());
    }

    return std::nullopt;
}

// modifiers

bool Engine::set_numa_config_from_option(const std::string& o) {
    if (o == "auto" || o == "system")
    {
        numaContext.set_numa_config(NumaConfig::from_system(DefaultNumaPolicy));
    }
    else if (o == "hardware")
    {
        // Don't respect affinity set in the system.
        numaContext.set_numa_config(NumaConfig::from_system(DefaultNumaPolicy, false));
    }
    else if (o == "none")
    {
        numaContext.set_numa_config(NumaConfig{});
    }
    else
    {
        auto parsed = NumaConfig::from_string(o);
        if (!parsed.has_value())
            return false;
        numaContext.set_numa_config(std::move(*parsed));
    }

    // Force reallocation of threads in case affinities need to change.
    resize_threads();
    threads.ensure_network_replicated();
    return true;
}

void Engine::resize_threads() {
    killer_check_join();
    threads.wait_for_search_finished();
    threads.set(numaContext.get_numa_config(), {options, threads, tt, sharedHists, network},
                updateContext);

    // Reallocate the hash with the new threadpool size
    set_tt_size(options["Hash"]);
    threads.ensure_network_replicated();
}

void Engine::set_tt_size(usize mb) {
    wait_for_search_finished();
    tt.resize(mb, threads);
}

void Engine::set_ponderhit(bool b) {
    std::lock_guard<std::mutex> lk(kpMutex);
    if (kpProbing)
        kpPonderhit = !b, kpPonderhitTime = now();
    else
        threads.main_manager()->ponder = b;
}

// network related

void Engine::verify_network() const {
    const auto file = path_from_utf8(EvalFileDefaultName);
    network->verify(onVerifyNetwork, networkFile, file);

    auto statuses = network.get_status_and_errors();
    for (usize i = 0; i < statuses.size(); ++i)
    {
        const auto [status, error] = statuses[i];
        std::string message        = "Network replica " + std::to_string(i + 1) + ": ";
        if (status == SystemWideSharedConstantAllocationStatus::NoAllocation)
        {
            message += "No allocation.";
        }
        else if (status == SystemWideSharedConstantAllocationStatus::LocalMemory)
        {
            message += "Local memory.";
        }
        else if (status == SystemWideSharedConstantAllocationStatus::SharedMemory)
        {
            message += "Shared memory.";
        }
        else
        {
            message += "Unknown status.";
        }

        if (error.has_value())
        {
            message += " " + *error;
        }

        onVerifyNetwork(message);
    }
}

std::unique_ptr<Eval::NNUE::Network> Engine::get_default_network() {

    auto network_ = std::make_unique<NN::Network>();

    network_->load(binaryDirectory, std::filesystem::path{}, networkFile);

    return network_;
}

void Engine::load_network(const std::filesystem::path& file) {
    network.modify_and_replicate(
      [this, &file](NN::Network& network_) { network_.load(binaryDirectory, file, networkFile); });
    threads.clear();
    threads.ensure_network_replicated();
}

void Engine::save_network(const std::optional<std::filesystem::path>& file) {
    network.modify_and_replicate(
      [&file, this](NN::Network& network_) { network_.save(networkFile, file); });
}

// utility functions

void Engine::trace_eval() const {
    StateListPtr trace_states(new std::deque<StateInfo>(1));
    Position     p;
    p.set(pos.fen(), &trace_states->back());

    verify_network();

    sync_cout << "\n" << Eval::trace(p, *network) << sync_endl;
}

const OptionsMap& Engine::get_options() const { return options; }
OptionsMap&       Engine::get_options() { return options; }

std::string Engine::fen() const { return pos.fen(); }

std::optional<PositionSetError> Engine::flip() {
    wait_for_search_finished();
    return pos.flip();
}

std::string Engine::visualize() const {
    std::stringstream ss;
    ss << pos;
    return ss.str();
}

int Engine::get_hashfull(int maxAge) const { return tt.hashfull(maxAge); }

std::vector<std::pair<usize, usize>> Engine::get_bound_thread_count_by_numa_node() const {
    auto                                 counts = threads.get_bound_thread_count_by_numa_node();
    const NumaConfig&                    cfg    = numaContext.get_numa_config();
    std::vector<std::pair<usize, usize>> ratios;
    NumaIndex                            n = 0;
    for (; n < counts.size(); ++n)
        ratios.emplace_back(counts[n], cfg.num_cpus_in_numa_node(n));
    if (!counts.empty())
        for (; n < cfg.num_numa_nodes(); ++n)
            ratios.emplace_back(0, cfg.num_cpus_in_numa_node(n));
    return ratios;
}

std::string Engine::get_numa_config_as_string() const {
    return numaContext.get_numa_config().to_string();
}

std::string Engine::numa_config_information_as_string() const {
    auto cfgStr = get_numa_config_as_string();
    return "Available processors: " + cfgStr;
}

std::string Engine::thread_binding_information_as_string() const {
    auto              boundThreadsByNode = get_bound_thread_count_by_numa_node();
    std::stringstream ss;
    if (boundThreadsByNode.empty())
        return ss.str();

    bool isFirst = true;

    for (auto&& [current, total] : boundThreadsByNode)
    {
        if (!isFirst)
            ss << ":";
        ss << current << "/" << total;
        isFirst = false;
    }

    return ss.str();
}

std::string Engine::thread_allocation_information_as_string() const {
    std::stringstream ss;

    usize threadsSize = threads.size();
    ss << "Using " << threadsSize << (threadsSize > 1 ? " threads" : " thread");

    const auto& pins = threads.get_core_pins();
    if (!pins.empty())
    {
        ss << " preferring physical cores (logical processors ";
        for (usize i = 0; i < pins.size(); ++i)
            ss << (i ? "," : "") << pins[i];
        ss << ")";
    }

    auto boundThreadsByNodeStr = thread_binding_information_as_string();
    if (boundThreadsByNodeStr.empty())
        return ss.str();

    ss << " with NUMA node thread binding: ";
    ss << boundThreadsByNodeStr;

    return ss.str();
}
}
