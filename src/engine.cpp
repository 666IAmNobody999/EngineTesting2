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
#include <filesystem>
#include <deque>
#include <initializer_list>
#include <iostream>
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
      Option("BestMove var BestMove var BareKing var HumanLike var HumanLikeBareKing var ForcedDraw",
             "BestMove",
             [this](const Option&) {
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
    // a few plies away, only captures (or, without any, moves that offer the
    // opponent a capture) are searched. When true it applies to
    //  * HumanLike / HumanLikeBareKing: always (any time control, pondering or not);
    //  * BestMove / BareKing: only at 0-1 s per move, a 1 minute game without
    //    increment, or in analysis;
    //  * Forced Draw: never.
    // When false it never applies.
    options.add(  //
      "Avoid_Sixty_Move_Draw", Option(true));

    options.add(  //
      "Repetition Rule",
      Option("SkyRule var SkyRule var AsianRule var QiZheRule var YiTianRule var ChineseRule var ComputerRule",
             "SkyRule", [this](const Option& o) {
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

                 // Couplings for AsianRule, SkyRule, ChineseRule and YiTianRule:
                 // all four rules use rule120 (弈天规则 26：无吃子着数达到 120 步判和；
                 // 亚象联第四节：双方共走 120 步未有去子作和), Rule60MaxPly stays freely
                 // adjustable 90-150, and the
                 // Sixty Move Rule is switched on for all three rules. The
                 // coupled options are assigned through the OptionsMap so that
                 // GUIs reflect the new defaults and the options' own callbacks
                 // keep RuleConfig in sync.
                 if (RuleConfig::repetitionRule == RR::ASIAN
                     || RuleConfig::repetitionRule == RR::SKY
					 || RuleConfig::repetitionRule == RR::CHINESE
                     || RuleConfig::repetitionRule == RR::YITIAN
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
          // The natural-move draw defaults on for every rule (including
          // YiTianRule) and can be freely toggled by the GUI; selecting
          // AsianRule/SkyRule/YiTianRule always switches it back on via the
          // Repetition Rule coupling.
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
// restrict the root to captures; without a capture, to moves after which the
// opponent can capture a piece (giving material away resets the counter too),
// never our last attacking piece.
// The search then picks the best of them. A forced mate (previous score) and an
// explicit searchmoves list are left alone; at the very last ply only a capture
// helps, so offers are not used there.
void Engine::avoid_sixty_move_draw(Search::LimitsType& limits) {
    constexpr int SixtyWindow = 6;

    if (!limits.searchmoves.empty() || limits.forceImproved || !options["Avoid_Sixty_Move_Draw"])
        return;

    // HumanLike / HumanLikeBareKing: always. BestMove / BareKing: only in a fast
    // game or analysis (sixtyFastGame). Forced Draw: never.
    const auto mode = Search::Attack::parse(options);
    if (mode == Search::AttackMode::FORCED_DRAW
        || (!Search::Attack::human_like(mode) && !sixtyFastGame))
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
        if (left < 2 || !captures.empty())
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
        limits.searchmoves = std::move(captures);
    else if (!offers.empty())
        limits.searchmoves = std::move(offers);
}

void Engine::stop() { threads.stop = true; }

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

void Engine::wait_for_search_finished() { threads.main_thread()->wait_for_search_finished(); }

std::optional<PositionSetError> Engine::set_position(const std::string&              fen,
                                                     const std::vector<std::string>& moves) {
    if (!HuanShen::LicenseGuard::ok())
        HWIDLock::is_authorized(std::string(options["License Key"]), nullptr, false);
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

void Engine::set_ponderhit(bool b) { threads.main_manager()->ponder = b; }

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

std::optional<PositionSetError> Engine::flip() { return pos.flip(); }

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
