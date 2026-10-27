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

#ifndef SEARCH_H_INCLUDED
#define SEARCH_H_INCLUDED

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <cstring>

#include "history.h"
#include "misc.h"
#include "nnue/nnue_accumulator.h"
#include "numa.h"
#include "position.h"
#include "score.h"
#include "timeman.h"
#include "types.h"

namespace Stockfish {

// Different node types, used as a template parameter
enum NodeType {
    NonPV,
    PV,
    Root
};

class TranspositionTable;
class ThreadPool;
class OptionsMap;

namespace Eval::NNUE {
class Network;
}

namespace Search {

// syzygy_extend_pv() may lead to PVs longer than MAX_PLY
struct RootPVMoves: public std::vector<Move> {
    RootPVMoves() { reserve(MAX_PLY); }
};

struct PVMoves {
    Move  moves[MAX_PLY + 1];
    usize length = 0;

    Move*       begin() { return moves; }
    const Move* begin() const { return moves; }
    Move*       end() { return moves + length; }
    const Move* end() const { return moves + length; }

    Move&       operator[](usize index) { return moves[index]; }
    const Move& operator[](usize index) const { return moves[index]; }

    bool  empty() const { return length == 0; }
    usize size() const { return length; }

    void clear() { length = 0; }

    void push_back(Move move) {
        assert(length < MAX_PLY + 1);
        moves[length++] = move;
    }

    void resize(usize newSize) {
        assert(newSize <= length);
        length = newSize;
    }

    void update(Move move, const PVMoves* childPv) {
        assert(childPv == nullptr || childPv->size() <= MAX_PLY);
        length = childPv ? childPv->length : 0;

        if (childPv)
            std::memcpy(moves + 1, childPv->moves, length * sizeof(Move));

        moves[0] = move;
        ++length;
    }

    PVMoves& operator=(const RootPVMoves& rhs) {
        length = std::min(rhs.size(), usize(MAX_PLY));
        std::memcpy(moves, rhs.data(), length * sizeof(Move));
        return *this;
    }
};

// Stack struct keeps track of the information we need to remember from nodes
// shallower and deeper in the tree during the search. Each search thread has
// its own array of Stack objects, indexed by the current ply.
struct Stack {
    PVMoves*                    pv;
    PieceToHistory*             continuationHistory;
    CorrectionHistory<PieceTo>* continuationCorrectionHistory;
    int                         ply;
    Move                        currentMove;
    Move                        excludedMove;
    Value                       staticEval;
    int                         statScore;
    int                         moveCount;
    bool                        inCheck;
    bool                        ttPv;
    bool                        ttHit;
    bool                        followPV;
    int                         cutoffCnt;
    int                         reduction;
    int                         priorNMPFailHigh;
};


// RootMove struct is used for moves at the root of the tree. For each root move
// we store a score and a PV (really a refutation in the case of moves which
// fail low). Score is normally set at -VALUE_INFINITE for all non-pv moves.
struct RootMove {

    explicit RootMove(Move m) { pv.push_back(m); }
    bool extract_ponder_from_tt(const TranspositionTable& tt, Position& pos);
    bool is_inexact() const { return inexactLower || inexactUpper; }
    bool is_exact_loss() const {
        return score != -VALUE_INFINITE && is_loss(score) && !is_inexact();
    }
    void unset_inexact() { inexactLower = inexactUpper = false; }
    bool operator==(const Move& m) const { return pv[0] == m; }
    // Sort in descending order
    bool operator<(const RootMove& m) const {
        return m.score != score ? m.score < score : m.previousScore < previousScore;
    }

    u64         effort           = 0;
    Value       score            = -VALUE_INFINITE;
    Value       previousScore    = -VALUE_INFINITE;
    Value       averageScore     = -VALUE_INFINITE;
    Value       meanSquaredScore = -VALUE_INFINITE * VALUE_INFINITE;
    Value       uciScore         = -VALUE_INFINITE;
    bool        inexactLower     = false;  // By default root scores are exact, unless flagged as a
    bool        inexactUpper     = false;  // one-sided bound here. See also `enum Bound` in types.h
    bool        previousScoreExact = false;
    int         selDepth           = 0;
    RootPVMoves pv, previousPV;
};

using RootMoves = std::vector<RootMove>;


// Skill structure is used to implement strength limit. If we have a UCI_Elo,
// we convert it to an appropriate skill level. The polynomial mapping comes from
// Stockfish (anchored there to CCRL 40/4); here it is rescaled to the
// [LowestElo, HighestElo] range of this engine and is a relative strength scale,
// not a calibrated Xiangqi rating.
// Attack Mode: how the engine converts its advantage.
//   BEST_MOVE   : normal search (no overhead at all).
//   BARE_KING   : once clearly winning, the evaluation seen by the search is
//                 dominated by the number of opponent pieces already captured,
//                 and a mate while the opponent still has pieces is worth less
//                 than capturing one more piece. The real mate score is only
//                 used against a bare king.
//   HUMAN_LIKE_BARE_KING : both of the above; the Human-like choice is made on
//                 the Bare King shaped scores.
//   FORCED_DRAW : the search runs as usual with MultiPV >= 6 and the root move
//                 whose score is closest to zero is played.
enum class AttackMode {
    BEST_MOVE,
    BARE_KING,
    HUMAN_LIKE,
    HUMAN_LIKE_BARE_KING,  // Bare King evaluation shaping + Human-like root choice
    FORCED_DRAW
};

// Search Algorithm option.
//   ORIGINAL          : plain iterative deepening, MultiPV as configured.
//   IMPROVED_MULTIPV2 : when MultiPV is 1 (and no Skill / Attack mode needs more
//                 lines) the main thread searches a second root line as in
//                 MultiPV 2, but its depth is capped at AltMaxDepth. Up to the cap
//                 the second best move is examined with a full window instead of a
//                 reduced null window; beyond the cap only the second line's own
//                 move is re-verified at the capped depth. The second line is not
//                 printed (GUIs and cloud front ends expect one line) and it is
//                 skipped while it is known to be more than AltWindowCp behind the
//                 main line or while the main line is already clearly winning. Promotion of the second line happens through the
//                 normal principal variation search of the next iteration, which
//                 is the only sound judge between scores of different depths.
enum class SearchAlgorithm {
    IMPROVED_MULTIPV2,
    ORIGINAL
};

namespace Improved {
constexpr Depth AltMaxDepth    = 20;   // depth cap of the second line
constexpr int   AltWindowCp    = 150;  // second line skipped when this far behind (cp)
constexpr Depth AltRecheckEvery = 4;   // ... but re-checked at least every N plies
constexpr int   AltMaxAdvantageCp = 24000;  // no second line once the main line is this far ahead

SearchAlgorithm parse(const OptionsMap& options);
}

namespace Attack {
// Which behaviours a mode switches on
constexpr bool bare_king(AttackMode m) {
    return m == AttackMode::BARE_KING || m == AttackMode::HUMAN_LIKE_BARE_KING;
}
constexpr bool human_like(AttackMode m) {
    return m == AttackMode::HUMAN_LIKE || m == AttackMode::HUMAN_LIKE_BARE_KING;
}

// Internal evaluation (side-to-move units) from which the Bare King shaping
// starts. 600 ~ cp 140 in the Elo score type, roughly 90% win probability.
constexpr Value Threshold = 600;
// Fixed value of each opponent piece already captured, on top of the (halved)
// NNUE evaluation.
constexpr Value PieceBonus = 500;
// A mate against a king that still has defenders is worth
// Threshold + PieceBonus * captured + EarlyMateBonus: one more capture (at least
// PieceBonus) is always preferred over it, while it still beats shuffling once
// the halved NNUE surplus over Threshold has fallen below this bonus.
constexpr Value EarlyMateBonus = 400;
// MultiPV lines examined by Forced Draw.
constexpr usize DrawMultiPV = 6;

// Human-like: with the best move worth more than HumanMinAdvantage (normalised
// centipawns, Elo score type units) there is a 1 in HumanChance probability of
// playing, instead of the best move, the searched root move that is between
// HumanMinDrop and HumanMaxDrop centipawns worse, preferring the smallest drop.
constexpr usize HumanMultiPV      = 4;
constexpr int   HumanChance       = 5;
constexpr int   HumanMinAdvantage = 100;
constexpr int   HumanMinDrop      = 50;
constexpr int   HumanMaxDrop      = 150;

// Reads the "Attack Mode" combo option.
AttackMode parse(const OptionsMap& options);
}

struct Skill {
    // Lowest and highest Elo ratings used in the skill level calculation
    constexpr static int LowestElo  = 1280;
    constexpr static int HighestElo = 3133;

    Skill(int skill_level, int uci_elo) {
        if (uci_elo)
        {
            double e = double(uci_elo - LowestElo) / (HighestElo - LowestElo);
            level = std::clamp((((37.2473 * e - 40.8525) * e + 22.2943) * e - 0.311438), 0.0, 19.0);
        }
        else
            level = double(skill_level);
    }
    bool enabled() const { return level < 20.0; }
    bool time_to_pick(Depth depth) const { return depth == 1 + int(level); }
    Move pick_best(const RootMoves&, usize multiPV);

    double level;
    Move   best = Move::none();
};


// LimitsType struct stores information sent by the caller about the analysis required.
struct LimitsType {

    // Init explicitly due to broken value-initialization of non POD in MSVC
    LimitsType() {
        time[WHITE] = time[BLACK] = inc[WHITE] = inc[BLACK] = npmsec = movetime = TimePoint(0);
        movestogo = depth = mate = perft = infinite = 0;
        nodes                                       = 0;
        ponderMode                                  = false;
    }

    bool use_time_management() const { return time[WHITE] || time[BLACK]; }

    std::vector<std::string> searchmoves;
    TimePoint                time[COLOR_NB], inc[COLOR_NB], npmsec, movetime, startTime;
    int                      movestogo, depth, mate, perft, infinite;
    u64                      nodes;
    bool                     ponderMode;
};


// The UCI stores the uci options, thread pool, and transposition table.
// This struct is used to easily forward data to the Search::Worker class.
struct SharedState {
    SharedState(const OptionsMap&                                        optionsMap,
                ThreadPool&                                              threadPool,
                TranspositionTable&                                      transpositionTable,
                std::map<NumaIndex, SharedHistories>&                    sharedHists,
                const LazyNumaReplicatedSystemWide<Eval::NNUE::Network>& net) :
        options(optionsMap),
        threads(threadPool),
        tt(transpositionTable),
        sharedHistories(sharedHists),
        network(net) {}

    const OptionsMap&                                        options;
    ThreadPool&                                              threads;
    TranspositionTable&                                      tt;
    std::map<NumaIndex, SharedHistories>&                    sharedHistories;
    const LazyNumaReplicatedSystemWide<Eval::NNUE::Network>& network;
};

class Worker;

struct InfoShort {
    int   depth;
    Score score;
};

struct InfoFull: InfoShort {
    int              selDepth;
    usize            multiPV;
    std::string_view wdl;
    std::string_view bound;
    usize            timeMs;
    usize            nodes;
    usize            nps;
    usize            tbHits;
    std::string_view pv;
    int              hashfull;
};

struct InfoIteration {
    int              depth;
    std::string_view currmove;
    usize            currmovenumber;
};

// SearchManager manages the search from the main thread. It is responsible for
// keeping track of the time, and storing data strictly related to the main thread.
class SearchManager {
   public:
    using UpdateShort    = std::function<void(const InfoShort&)>;
    using UpdateFull     = std::function<void(const InfoFull&)>;
    using UpdateIter     = std::function<void(const InfoIteration&)>;
    using UpdateBestmove = std::function<void(std::string_view, std::string_view)>;
    using UpdateStart    = std::function<void()>;

    struct UpdateContext {
        UpdateShort    onUpdateNoMoves;
        UpdateFull     onUpdateFull;
        UpdateIter     onIter;
        UpdateBestmove onBestmove;
        UpdateStart    onStart;
    };


    SearchManager(const UpdateContext& updateContext) :
        updates(updateContext) {}

    void check_time(Search::Worker& worker);

    void output_pv(Search::Worker&           worker,
                   const ThreadPool&         threads,
                   const TranspositionTable& tt,
                   Depth                     depth);

    Stockfish::TimeManagement tm;
    double                    originalTimeAdjust;
    int                       callsCnt;
    std::atomic_bool          ponder;

    std::array<Value, 4> iterValue;
    double               previousTimeReduction;
    Value                bestPreviousScore;
    Value                bestPreviousAverageScore;
    bool                 stopOnPonderhit;

    const UpdateContext& updates;
};

// Search::Worker is the class that does the actual search.
// It is instantiated once per thread, and it is responsible for keeping track
// of the search history, and storing data required for the search.
class Worker {
   public:
    Worker(
      SharedState&, std::unique_ptr<SearchManager>, usize, usize, usize, NumaReplicatedAccessToken);

    // Called at instantiation to initialize reductions tables.
    // Reset histories, usually before a new game.
    void clear();

    // Called when the program receives the UCI 'go' command.
    // It searches from the root position and outputs the "bestmove".
    void start_searching();

    bool is_mainthread() const { return threadIdx == 0; }

    void ensure_network_replicated();

    // Public because they need to be updatable by the stats
    ButterflyHistory mainHistory;
    LowPlyHistory    lowPlyHistory;

    CapturePieceToHistory           captureHistory;
    CorrectionHistory<Continuation> continuationCorrectionHistory;

    TTMoveHistory    ttMoveHistory;
    SharedHistories& sharedHistory;
    ContinuationHistory (&continuationHistory)[2][2];

   private:
    bool iterative_deepening();

    void do_move(Position& pos, const Move move, StateInfo& st, Stack* const ss);
    void do_move(Position&    pos,
                 const Move   move,
                 StateInfo&   st,
                 const bool   givesCheck,
                 const bool   capture,
                 Stack* const ss);
    void do_null_move(Position& pos, StateInfo& st, Stack* const ss);
    void undo_move(Position& pos, const Move move);
    void undo_null_move(Position& pos);

    // This is the main search function, for both PV and non-PV nodes
    template<NodeType nodeType>
    Value
    search(Position& pos, Stack* ss, Value alpha, Value beta, Depth depth, const bool cutNode);

    // Quiescence search function, which is called by the main search
    template<NodeType nodeType>
    Value qsearch(Position& pos, Stack* ss, Value alpha, Value beta);

    int reduction(bool i, Depth d, int mn, int delta) const;

    // Pointer to the search manager, only allowed to be called by the main thread
    SearchManager* main_manager() const {
        assert(threadIdx == 0);
        assert(manager.get() != nullptr);
        return manager.get();
    }

    TimePoint elapsed() const;

    Value evaluate(const Position&);

    LimitsType limits;

    usize              pvIdx, pvLast;
    Value              altScore      = -VALUE_INFINITE;  // last exact score of the second line
    Depth              altScoreDepth = 0;                // ... and the iteration it was obtained in
    RelaxedAtomic<u64> nodes, bestMoveChanges;
    int                selDepth, nmpMinPly;

    Value optimism[COLOR_NB];

    Position  rootPos;
    StateInfo rootState;
    RootMoves rootMoves;
    Depth     rootDepth;
    Color     rootColor  = WHITE;
    AttackMode attackMode = AttackMode::BEST_MOVE;

    // Bare King helpers (see AttackMode). Both are no-ops in BEST_MOVE mode.
    Value attack_shape_eval(Value v, const Position& pos) const;
    Value attack_shape_win(Value v, const Position& pos, int ply) const;
    bool      seekMate = false;
    Value     rootDelta;

    PVMoves lastIterationIdxPV;

    usize                     threadIdx, numaThreadIdx, numaTotal;
    NumaReplicatedAccessToken numaAccessToken;

    // Reductions lookup table initialized at startup
    std::array<int, MAX_PLY + 10> reductions;  // [depth or moveNumber]

    // The main thread has a SearchManager, the others have a nullptr
    std::unique_ptr<SearchManager> manager;

    const OptionsMap&                                        options;
    ThreadPool&                                              threads;
    TranspositionTable&                                      tt;
    const LazyNumaReplicatedSystemWide<Eval::NNUE::Network>& network;

    // Used by NNUE
    Eval::NNUE::AccumulatorStack  accumulatorStack;
    Eval::NNUE::AccumulatorCaches refreshTable;

    friend class Stockfish::ThreadPool;
    friend class SearchManager;
};

struct ConthistBonus {
    int index;
    int weight;
};


}  // namespace Search

}  // namespace Stockfish

#endif  // #ifndef SEARCH_H_INCLUDED
