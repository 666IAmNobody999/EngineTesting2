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

#include "position.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cctype>
#include <cstddef>
#include <initializer_list>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string_view>
#include <utility>
#include <vector>

#include "attacks.h"
#include "bitboard.h"
#include "history.h"
#include "misc.h"
#include "movegen.h"
#include "nnue/nnue_common.h"
#include "nnue/nnue_architecture.h"
#include "tt.h"
#include "uci.h"

using std::string;

namespace Stockfish {

using namespace Attacks;

namespace RuleConfig {
// Defaults: SkyRule with rule120, Sixty Move Rule on.
// AsianRule/SkyRule/ChineseRule/YitianRule all couple to rule120 and keep the
// Sixty Move Rule on (enforced in engine.cpp couplings).
RepetitionRule repetitionRule  = RepetitionRule::SKY;
DrawRule       drawRule        = DrawRule::NONE;
int            mateThreatDepth = 2;
bool           sixtyMoveRule   = true;
int            rule60MaxPly    = 120;
int            rule60Limit     = 120;
int            rule60KeyCap    = 120;
int            rule60EvalDiv   = 244;

void refresh_rule60() {
    const int maxPly = std::max(1, rule60MaxPly);
    rule60Limit      = sixtyMoveRule ? maxPly : RULE60_UNLIMITED;
    // With the rule off keep the upstream rule-120 shape for the TT buckets and the
    // evaluation damping instead of letting the counter run away.
    rule60KeyCap  = sixtyMoveRule ? maxPly : 120;
    rule60EvalDiv = 2 * rule60KeyCap + 4;
}
}  // namespace RuleConfig

namespace {

// StateInfo::skyChasers doubles as the "SkyRule info computed" marker. Kings and
// pawns never chase, so a real chaser mask can never have all 16 bits set.
constexpr u16 SKY_UNCOMPUTED = 0xFFFF;

// Sky info is written into StateInfo objects that may be shared by several search
// threads (the game history before the root). Every thread computes identical
// values, so the only requirement is that the marker becomes visible last.
inline bool sky_cached(const StateInfo* s) {
#if defined(__GNUC__) || defined(__clang__)
    return __atomic_load_n(&s->skyChasers, __ATOMIC_ACQUIRE) != SKY_UNCOMPUTED;
#else
    return s->skyChasers != SKY_UNCOMPUTED;
#endif
}

inline void sky_publish(StateInfo* s, u16 victims, u16 checkers, u16 chasers) {
    s->skyVictims  = victims;
    s->skyCheckers = checkers;
#if defined(__GNUC__) || defined(__clang__)
    __atomic_store_n(&s->skyChasers, chasers, __ATOMIC_RELEASE);
#else
    s->skyChasers = chasers;
#endif
}

inline void sky_invalidate(StateInfo* s) {
    s->skyVictims  = 0;
    s->skyCheckers = 0;
    s->skyChasers  = SKY_UNCOMPUTED;
}

}  // namespace

namespace Zobrist {

Key psq[PIECE_NB][SQUARE_NB];
Key side, noPawns;
}

namespace {

constexpr std::string_view PieceToChar(" RACPNBK racpnbk");

static constexpr Piece Pieces[] = {W_ROOK, W_ADVISOR, W_CANNON, W_PAWN, W_KNIGHT, W_BISHOP, W_KING,
                                   B_ROOK, B_ADVISOR, B_CANNON, B_PAWN, B_KNIGHT, B_BISHOP, B_KING};
}  // namespace

// Returns an ASCII representation of the position
std::ostream& operator<<(std::ostream& os, const Position& pos) {

    os << "\n +---+---+---+---+---+---+---+---+---+\n";

    for (Rank r = RANK_9;; --r)
    {
        for (File f = FILE_A; f <= FILE_I; ++f)
            os << " | " << PieceToChar[pos.piece_on(make_square(f, r))];

        os << " | " << int(r) << "\n +---+---+---+---+---+---+---+---+---+\n";

        if (r == RANK_0)
            break;
    }

    os << "   a   b   c   d   e   f   g   h   i\n"
       << "\nFen: " << pos.fen() << "\nKey: " << std::hex << std::uppercase << std::setfill('0')
       << std::setw(16) << pos.key() << std::setfill(' ') << std::dec << "\nCheckers: ";

    for (Bitboard b = pos.checkers(); b;)
        os << UCIEngine::square(pop_lsb(b)) << " ";

    return os;
}


// Initializes at startup the various arrays used to compute hash keys
void Position::init() {

    PRNG rng(1070372);

    for (Piece pc : Pieces)
        for (Square s = SQ_A0; s <= SQ_I9; ++s)
            Zobrist::psq[pc][s] = rng.rand<Key>();

    Zobrist::side    = rng.rand<Key>();
    Zobrist::noPawns = rng.rand<Key>();
}


// Initializes the position object with the given FEN string.
// The FEN string is strictly validated; if it is invalid or inconsistent,
// a PositionSetError describing the problem is returned, otherwise std::nullopt.
std::optional<PositionSetError> Position::set(const string& fenStr, StateInfo* si) {
    /*
   A FEN string defines a particular position using only the ASCII character set.

   A FEN string contains six fields separated by a space. The fields are:

   1) Piece placement (from white's perspective). Each rank is described, starting
      with rank 9 and ending with rank 0. Within each rank, the contents of each
      square are described from file A through file I. Following the Standard
      Algebraic Notation (SAN), each piece is identified by a single letter taken
      from the standard English names. White pieces are designated using upper-case
      letters ("RACPNBK") whilst Black uses lowercase ("racpnbk"). Blank squares are
      noted using digits 1 through 9 (the number of blank squares), and "/"
      separates ranks.

   2) Active color. "w" means white moves next, "b" means black.

   3) Halfmove clock. This is the number of halfmoves since the last pawn advance
      or capture. This is used to determine if a draw can be claimed under the
      fifty-move rule.

   4) Fullmove number. The number of the full move. It starts at 1, and is
      incremented after Black's move.
*/

    unsigned char      token;
    std::istringstream ss(fenStr);

    std::memset(reinterpret_cast<char*>(this), 0, sizeof(Position));
    std::memset(si, 0, sizeof(StateInfo));
    st = si;

    midEncoding[WHITE] = midEncoding[BLACK] = Eval::NNUE::Features::HalfKAv2_hm::BalanceEncoding;

    ss >> std::noskipws;

    int numPieces = 0;
    int file      = FILE_A;
    int rank      = RANK_9;

    // 1. Piece placement
    for (;;)
    {
        if (!(ss >> token))
            return PositionSetError("Invalid FEN. Unexpected end of stream.");

        if (isspace(token))
            break;

        if (isdigit(token))
        {
            const int diff = (token - '0');
            if (diff < 1)
                return PositionSetError("Invalid FEN. Invalid number of squares to skip.");

            file += diff;
            if (file > FILE_NB)
                return PositionSetError("Invalid FEN. Invalid file reached.");
        }
        else if (token == '/')
        {
            if (file != FILE_NB)
                return PositionSetError(
                  "Invalid FEN. Trying to end rank when not at the end of it.");

            --rank;
            file = FILE_A;

            if (rank < RANK_0)
                return PositionSetError("Invalid FEN. Invalid rank reached.");
        }
        else
        {
            if (file >= FILE_NB)
                return PositionSetError("Invalid FEN. Invalid file reached.");

            const usize idx = PieceToChar.find(token);
            if (idx == string::npos)
                return PositionSetError(std::string("Invalid FEN. Invalid piece: ")
                                        + std::string(1, token));

            if (++numPieces > 32)
                return PositionSetError("Invalid FEN. More than 32 pieces on the board.");

            const Square sq = make_square(File(file), Rank(rank));
            put_piece(Piece(idx), sq);

            ++file;
        }
    }

    if (rank != RANK_0 || file != FILE_NB)
        return PositionSetError("Invalid FEN. Board state encoding ended but cursor not at end.");

    if (count<KING>(WHITE) != 1 || count<KING>(BLACK) != 1)
        return PositionSetError("Unsupported position. Incorrect number of kings.");

    const std::string PieceTypeToStr[PIECE_TYPE_NB] = {"",     "rook",   "advisor", "cannon",
                                                       "pawn", "knight", "bishop",  "king"};
    constexpr int     MaxPieces[PIECE_TYPE_NB - 1]  = {0, 2, 2, 2, 5, 2, 2};
    for (Color c : {WHITE, BLACK})
    {
        for (PieceType pt = ROOK; pt < KING; ++pt)
            if (popcount(pieces(c, pt)) > MaxPieces[pt])
                return PositionSetError(std::string("Unsupported position. ")
                                        + (c == WHITE ? "WHITE " : "BLACK ") + "has more than "
                                        + std::to_string(MaxPieces[pt]) + " " + PieceTypeToStr[pt]
                                        + "s.");

        for (PieceType pt : {ADVISOR, PAWN, BISHOP, KING})
        {
            Bitboard valid = Eval::NNUE::Features::HalfKAv2_hm::ValidBB[make_piece(c, pt)];
            // NNUE mirroring feature does not allow white king on the right flank, we allow here.
            if (c == WHITE && pt == KING)
                valid = HalfBB[WHITE] & Palace;
            if (pieces(c, pt) & ~valid)
                return PositionSetError(std::string("Unsupported position. ")
                                        + (c == WHITE ? "WHITE " : "BLACK ") + PieceTypeToStr[pt]
                                        + "(s) on invalid positions.");
        }
    }

    // 2. Active color
    if (!(ss >> token))
        return PositionSetError("Invalid FEN. Unexpected end of stream.");
    if (token != 'w' && token != 'b')
        return PositionSetError(std::string("Invalid FEN. Invalid side to move: ")
                                + std::string(1, token));
    sideToMove = (token == 'w' ? WHITE : BLACK);
    if (!(ss >> token) || !isspace(token) || ss.eof())
        return PositionSetError("Invalid FEN. Expected whitespace after side to move.");

    while ((ss >> token) && !isspace(token))
        ;

    while ((ss >> token) && !isspace(token))
        ;

    // 3-4. Halfmove clock and fullmove number
    ss >> std::skipws >> st->rule60 >> gamePly;

    // With the Sixty Move Rule off any counter is acceptable (the game simply goes
    // on); with it on, a position at or beyond the limit is already over.
    if (st->rule60 < 0 || st->rule60 >= RuleConfig::rule60Limit)
        return PositionSetError("Unsupported position. Rule60 counter out of range.");

    if (gamePly < 0 || gamePly > 100000)
        return PositionSetError("Unsupported position. Game ply out of range.");

    // Convert from fullmove starting from 1 to gamePly starting from 0,
    // handle also common incorrect FEN with fullmove = 0.
    gamePly = std::max(2 * (gamePly - 1), 0) + (sideToMove == BLACK);

    // Persistent per-colour piece identities (0..15) used by the chase detectors.
    // They follow the pieces in do_move()/undo_move(), so the SkyRule information
    // attached to a StateInfo stays valid for as long as that state exists.
    {
        int whiteId = 0, blackId = 0;
        for (Square s = SQ_A0; s <= SQ_I9; ++s)
            if (board[s] != NO_PIECE)
                idBoard[s] = color_of(board[s]) == WHITE ? whiteId++ : blackId++;
    }

    set_state();

    if (checkers_to(sideToMove, king_square(~sideToMove)))
        return PositionSetError("Unsupported position. King can be captured.");

    assert(pos_is_ok());

    return std::nullopt;
}


// Sets pinners, where stm can give check and invalidates the threat cache.
void Position::set_extra_bitboards() const {

    update_blockers<WHITE>();
    update_blockers<BLACK>();

    Square ksq = king_square(~sideToMove);

    // We have to take special cares about the hollow cannons and checks
    st->needFullCheck =
      checkers() || (attacks_bb(ROOK, king_square(sideToMove)) & pieces(~sideToMove, CANNON));

    st->checkSquares[PAWN]   = attacks_bb(PAWN_TO, ksq, sideToMove);
    st->checkSquares[KNIGHT] = attacks_bb(KNIGHT_TO, ksq, pieces());
    st->checkSquares[CANNON] = attacks_bb(CANNON, ksq, pieces());
    st->checkSquares[ROOK]   = attacks_bb(ROOK, ksq, pieces());
    st->checkSquares[KING] = st->checkSquares[ADVISOR] = st->checkSquares[BISHOP] = 0;

    st->threatsComputed = false;

    Bitboard hollowCannons = st->checkSquares[ROOK] & pieces(sideToMove, CANNON);
    if (hollowCannons)
    {
        Bitboard hollowCannonDiscover = Bitboard(0);
        while (hollowCannons)
            hollowCannonDiscover |= between_bb(pop_lsb(hollowCannons), ksq);
        for (PieceType pt = ROOK; pt < KING; ++pt)
            st->checkSquares[pt] |= hollowCannonDiscover;
    }
}


// Computes the threat cache only when move generation or scoring needs it.
// Squares threatened by ~sideToMove, including x-ray attacks through our king
// (this only matters when sideToMove is in check).
void Position::set_threats() const {

    Bitboard occ            = pieces() ^ king_square(sideToMove);
    st->threats[ALL_PIECES] = st->threats[PAWN]     = xattacks_by(PAWN, ~sideToMove, occ);
    st->threats[ALL_PIECES] |= st->threats[BISHOP]  = xattacks_by(BISHOP, ~sideToMove, occ);
    st->threats[ALL_PIECES] |= st->threats[ADVISOR] = xattacks_by(ADVISOR, ~sideToMove, occ);
    st->threats[ALL_PIECES] |= st->threats[KNIGHT]  = xattacks_by(KNIGHT, ~sideToMove, occ);
    st->threats[ALL_PIECES] |= st->threats[CANNON]  = xattacks_by(CANNON, ~sideToMove, occ);
    st->threats[ALL_PIECES] |= st->threats[ROOK]    = xattacks_by(ROOK, ~sideToMove, occ);
    st->threats[ALL_PIECES] |= st->threats[KING]    = xattacks_by(KING, ~sideToMove, occ);
    st->threatsComputed                             = true;
}


// Computes the hash keys of the position, and other
// data that once computed is updated incrementally as moves are made.
// The function is only used when a new position is set up
void Position::set_state() const {

    st->key               = 0;
    st->minorPieceKey     = 0;
    st->nonPawnKey[WHITE] = st->nonPawnKey[BLACK] = 0;
    st->pawnKey                                   = Zobrist::noPawns;
    st->majorMaterial[WHITE] = st->majorMaterial[BLACK] = VALUE_ZERO;
    st->checkersBB = checkers_to(~sideToMove, king_square(sideToMove));
    st->move       = Move::none();
    st->skyCapturedId = 0;
    sky_invalidate(st);

    set_extra_bitboards();

    for (Bitboard b = pieces(); b;)
    {
        Square    s  = pop_lsb(b);
        Piece     pc = piece_on(s);
        PieceType pt = type_of(pc);
        st->key ^= Zobrist::psq[pc][s];

        if (pt == PAWN)
            st->pawnKey ^= Zobrist::psq[pc][s];

        else
        {
            st->nonPawnKey[color_of(pc)] ^= Zobrist::psq[pc][s];

            if (pt != KING && (pt & 1))
            {
                st->majorMaterial[color_of(pc)] += PieceValue[pc];
                if (pt != ROOK)
                    st->minorPieceKey ^= Zobrist::psq[pc][s];
            }
        }
    }

    if (sideToMove == BLACK)
        st->key ^= Zobrist::side;
}


// Returns a FEN representation of the position.
string Position::fen() const {

    int                emptyCnt;
    std::ostringstream ss;

    for (Rank r = RANK_9;; --r)
    {
        for (File f = FILE_A; f <= FILE_I; ++f)
        {
            for (emptyCnt = 0; f <= FILE_I && empty(make_square(f, r)); ++f)
                ++emptyCnt;

            if (emptyCnt)
                ss << emptyCnt;

            if (f <= FILE_I)
                ss << PieceToChar[piece_on(make_square(f, r))];
        }

        if (r == RANK_0)
            break;
        ss << '/';
    }

    ss << (sideToMove == WHITE ? " w " : " b ");

    ss << '-';

    ss << " - " << st->rule60 << " " << 1 + (gamePly - (sideToMove == BLACK)) / 2;

    return ss.str();
}


// Calculates st->blockersForKing[c] and st->pinners[~c],
// which store respectively the pieces preventing king of color c from being in check
// and the slider pieces of color ~c pinning pieces of color c to the king.
template<Color c>
void Position::update_blockers() const {

    Square ksq             = king_square(c);
    st->blockersForKing[c] = 0;
    st->pinners[~c]        = 0;

    // Snipers are pieces that attack 's' when a piece and other pieces are removed
    Bitboard snipers   = ((attacks_bb(ROOK, ksq) & (pieces(ROOK) | pieces(CANNON) | pieces(KING)))
                          | (attacks_bb(KNIGHT, ksq) & pieces(KNIGHT)))
                       & pieces(~c);
    Bitboard occupancy = pieces() ^ (snipers & ~pieces(CANNON));

    while (snipers)
    {
        Square   sniperSq = pop_lsb(snipers);
        bool     isCannon = type_of(piece_on(sniperSq)) == CANNON;
        Bitboard b = between_bb(ksq, sniperSq) & (isCannon ? pieces() ^ sniperSq : occupancy);

        if (b && ((!isCannon && !more_than_one(b)) || (isCannon && popcount(b) == 2)))
        {
            st->blockersForKing[c] |= b;
            if (b & pieces(c))
                st->pinners[~c] |= sniperSq;
        }
    }
}


// Computes a bitboard of all pieces which attack a given square.
// Slider attacks use the occupied bitboard to indicate occupancy.
Bitboard Position::attackers_to(Square s, Bitboard occupied) const {

    return (attacks_bb(PAWN_TO, s, WHITE) & pieces(WHITE, PAWN))
         | (attacks_bb(PAWN_TO, s, BLACK) & pieces(BLACK, PAWN))
         | (attacks_bb(KNIGHT_TO, s, occupied) & pieces(KNIGHT))
         | (attacks_bb(ROOK, s, occupied) & pieces(ROOK))
         | (attacks_bb(CANNON, s, occupied) & pieces(CANNON))
         | (attacks_bb(BISHOP, s, occupied) & pieces(BISHOP))
         | (attacks_bb(ADVISOR, s) & pieces(ADVISOR)) | (attacks_bb(KING, s) & pieces(KING));
}


// Computes a bitboard of all pieces of a given color
// which gives check to a given square. Slider attacks use the occupied bitboard
// to indicate occupancy.
Bitboard Position::checkers_to(Color c, Square s, Bitboard occupied) const {

    return ((attacks_bb(PAWN_TO, s, c) & pieces(PAWN))
            | (attacks_bb(KNIGHT_TO, s, occupied) & pieces(KNIGHT))
            | (attacks_bb(ROOK, s, occupied) & pieces(KING, ROOK))
            | (attacks_bb(CANNON, s, occupied) & pieces(CANNON)))
         & pieces(c);
}


// Takes a random move and tests whether the move is legal. It is used to validate moves
// from TT that can be corrupted due to SMP concurrent access or hash position key aliasing.
// Move generation itself only produces legal moves, so the search never calls this on
// generated moves.
bool Position::legal(Move m) const {

    if (!m.is_ok() || !is_ok(m.from_sq()) || !is_ok(m.to_sq()))
        return false;

    Color  us   = sideToMove;
    Square from = m.from_sq();
    Square to   = m.to_sq();
    Piece  pc   = moved_piece(m);

    // If the 'from' square is not occupied by a piece belonging to the side to
    // move, the move is obviously not legal.
    if (pc == NO_PIECE || color_of(pc) != us)
        return false;

    // The destination square cannot be occupied by a friendly piece
    if (pieces(us) & to)
        return false;

    // Handle the special cases
    if (type_of(pc) == PAWN)
    {
        if (!(attacks_bb(PAWN, from, us) & to))
            return false;
    }
    else if (type_of(pc) == CANNON && !capture(m))
    {
        if (!(attacks_bb(ROOK, from, pieces()) & to))
            return false;
    }
    else if (!(attacks_bb(type_of(pc), from, pieces()) & to))
        return false;

    Bitboard occupied = (pieces() ^ from) | to;

    // If the moving piece is a king, check whether the destination square is
    // attacked by the opponent.
    if (type_of(piece_on(from)) == KING)
        return !(to & threats_by(ALL_PIECES));

    // If we don't need full check. A non-king move is always legal when either:
    // 1. Not moving a pinned piece.
    // 2. Moving a pinned non-cannon piece and aligned with king.
    // 3. Moving a pinned cannon and aligned with king but it's not a capture move.
    if (!st->needFullCheck
        && (!(blockers_for_king(us) & from)
            || (((type_of(piece_on(from)) != CANNON) || !capture(m))
                && aligned(from, to, king_square(us)))))
        return true;

    // A non-king move is legal if the king is not under attack after the move.
    return !(checkers_to(~us, king_square(us), occupied) & ~square_bb(to));
}


// Tests whether a legal move gives a check
bool Position::gives_check(Move m) const {

    assert(m.is_ok());
    assert(color_of(moved_piece(m)) == sideToMove);

    Square from = m.from_sq();
    Square to   = m.to_sq();
    Square ksq  = king_square(~sideToMove);

    PieceType pt = type_of(moved_piece(m));

    // Is there a direct check?
    if (pt == CANNON && (check_squares(ROOK) & from) && aligned(from, to, ksq))
    {
        if (capture(m) && (ray_pass_bb(ksq, from) & to))
            return true;
    }
    else if (check_squares(pt) & to)
        return true;

    // Is there a discovered check?
    if ((blockers_for_king(~sideToMove) & from) && (!aligned(from, to, ksq) || capture(m)))
        return true;

    return false;
}


// Makes a move, and saves all information necessary
// to a StateInfo object. The move is assumed to be legal. Pseudo-legal
// moves should be filtered out before this function is called.
// If a pointer to the TT table is passed, the entry for the new position
// will be prefetched, and likewise for shared history.
void Position::do_move(Move                      m,
                       StateInfo&                newSt,
                       bool                      givesCheck,
                       Dirties&                  dirties,
                       const TranspositionTable* tt      = nullptr,
                       const SharedHistories*    history = nullptr) {

    using namespace Eval::NNUE;

    assert(m.is_ok());
    assert(&newSt != st);

    // Update the bloom filter
    ++filter[st->key];

    Key k = st->key ^ Zobrist::side;

    // Copy some fields of the old state to our new StateInfo object except the
    // ones which are going to be recalculated from scratch anyway and then switch
    // our state pointer to point to the new (ready to be updated) state.
    std::memcpy(&newSt, st, offsetof(StateInfo, key));
    newSt.previous = st;
    st             = &newSt;
    st->move       = m;
    sky_invalidate(st);

    // Increment ply counters. Clamp to 10 checks for each side in rule 60
    // In particular, rule60 will be reset to zero later on in case of a capture.
    ++gamePly;
    if (!givesCheck || ++st->check10[sideToMove] <= 10)
    {
        if (st->check10[~sideToMove] > 10 && st->previous->checkersBB)
            ++st->check10[~sideToMove];
        else
            ++st->rule60;
    }
    ++st->pliesFromNull;

    auto& dts = dirties.dirtyThreats;
    auto& dp  = dirties.dirtyPiece;

    Color  us       = sideToMove;
    Color  them     = ~us;
    Square from     = m.from_sq();
    Square to       = m.to_sq();
    Piece  pc       = piece_on(from);
    Piece  captured = piece_on(to);

    dp.pc   = pc;
    dp.from = from;
    dp.to   = to;

    assert(color_of(pc) == us);
    assert(captured == NO_PIECE || color_of(captured) == them);
    assert(type_of(captured) != KING);

    if (captured)
    {
        Square capsq = to;

        // If the captured piece is a pawn, update pawn hash key, otherwise
        // update major material.
        if (type_of(captured) == PAWN)
            st->pawnKey ^= Zobrist::psq[captured][capsq];

        else
        {
            st->nonPawnKey[them] ^= Zobrist::psq[captured][capsq];

            if (type_of(captured) & 1)
            {
                st->majorMaterial[them] -= PieceValue[captured];
                if (type_of(captured) != ROOK)
                    st->minorPieceKey ^= Zobrist::psq[captured][capsq];
            }
        }

        dp.remove_pc = captured;
        dp.remove_sq = capsq;

        // Update hash key
        k ^= Zobrist::psq[captured][capsq];

        // Reset rule 60 counter
        st->check10[WHITE] = st->check10[BLACK] = st->rule60 = 0;
    }
    else
        dp.remove_sq = SQ_NONE;

    // Update hash key
    k ^= Zobrist::psq[pc][from] ^ Zobrist::psq[pc][to];
    if (tt)
        prefetch(tt->first_entry(adjust_key60(k)));
    // Update the key with the final value
    st->key = k;

    // If the moving piece is a pawn, update pawn hash key.
    if (type_of(pc) == PAWN)
        st->pawnKey ^= Zobrist::psq[pc][from] ^ Zobrist::psq[pc][to];
    else
    {
        st->nonPawnKey[us] ^= Zobrist::psq[pc][from] ^ Zobrist::psq[pc][to];

        if (type_of(pc) == KNIGHT || type_of(pc) == CANNON)
            st->minorPieceKey ^= Zobrist::psq[pc][from] ^ Zobrist::psq[pc][to];
    }

    if (history)
    {
        prefetch(&history->pawn_entry(*this)[pc][to]);
        prefetch(&history->pawn_correction_entry(*this));
        prefetch(&history->minor_piece_correction_entry(*this));
        prefetch(&history->nonpawn_correction_entry<WHITE>(*this));
        prefetch(&history->nonpawn_correction_entry<BLACK>(*this));
    }

    bool mirror_before[2] = {
      PSQFeatureSet::KingBuckets[king_square(us)][king_square(them)]
                                [PSQFeatureSet::requires_mid_mirror(*this, us)]
                                  .second,
      PSQFeatureSet::KingBuckets[king_square(them)][king_square(us)]
                                [PSQFeatureSet::requires_mid_mirror(*this, them)]
                                  .second};
    dp.requires_refresh[them] = false;
    dp.requires_refresh[us]   = pc == make_piece(us, KING);

    if (captured)
    {
        auto attack_bucket_before = PSQFeatureSet::make_attack_bucket(*this, them);

        remove_piece(from, &dts);
        swap_piece(to, pc, &dts);

        auto attack_bucket_after = PSQFeatureSet::make_attack_bucket(*this, them);

        dp.requires_refresh[them] |= (attack_bucket_before != attack_bucket_after);
    }
    else
        move_piece(from, to, &dts);

    bool mirror_after[2] = {
      PSQFeatureSet::KingBuckets[king_square(us)][king_square(them)]
                                [PSQFeatureSet::requires_mid_mirror(*this, us)]
                                  .second,
      PSQFeatureSet::KingBuckets[king_square(them)][king_square(us)]
                                [PSQFeatureSet::requires_mid_mirror(*this, them)]
                                  .second};
    dp.requires_refresh[us] |= (mirror_before[0] != mirror_after[0]);
    dp.requires_refresh[them] |= (mirror_before[1] != mirror_after[1]);

    // Set capture piece
    st->capturedPiece = captured;

    // Keep the persistent piece identities in step with the board
    st->skyCapturedId = idBoard[to];
    idBoard[to]       = idBoard[from];
    idBoard[from]     = 0;

    // Calculate checkers bitboard (if move gives check)
    st->checkersBB = givesCheck ? checkers_to(us, king_square(them)) : Bitboard(0);
    assert(givesCheck == bool(checkers_to(us, king_square(them))));

    sideToMove = ~sideToMove;

    // Update king attacks used for fast check detection
    set_extra_bitboards();

    assert(pos_is_ok());

    assert(dp.pc != NO_PIECE);
    assert(!bool(captured) ^ (dp.remove_sq != SQ_NONE));
    assert(dp.from != SQ_NONE && dp.to != SQ_NONE);
}


// Unmakes a move. When it returns, the position should
// be restored to exactly the same state as before the move was made.
void Position::undo_move(Move m) {

    assert(m.is_ok());

    sideToMove = ~sideToMove;

    Square from = m.from_sq();
    Square to   = m.to_sq();

    assert(empty(from));
    assert(type_of(st->capturedPiece) != KING);

    // Put back the persistent piece identities (0 when nothing was captured)
    idBoard[from] = idBoard[to];
    idBoard[to]   = st->skyCapturedId;

    move_piece(to, from);  // Put the piece back at the source square

    if (st->capturedPiece)
    {
        Square capsq = to;

        put_piece(st->capturedPiece, capsq);  // Restore the captured piece
    }

    // Finally point our state pointer back to the previous state
    st = st->previous;
    --gamePly;

    // Update the bloom filter
    --filter[st->key];

    assert(pos_is_ok());
}

inline void add_dirty_threat(DirtyThreats* const dts,
                             bool                PutPiece,
                             Piece               pc,
                             Piece               threatened,
                             Square              s,
                             Square              threatenedSq) {
    dts->list.push_back({pc, threatened, s, threatenedSq, PutPiece});
}


template<bool ComputeRay>
void Position::update_piece_threats(Piece pc, bool putPiece, Square s, DirtyThreats* const dts) {
    Bitboard occupied = pieces();

    const Bitboard rAttacks = attacks_bb(ROOK, s, occupied);
    const Bitboard cAttacks = attacks_bb(CANNON, s, occupied);

    // Outgoing threats
    Bitboard threatened;

    switch (type_of(pc))
    {
    case PAWN :
        threatened = attacks_bb(PAWN, s, color_of(pc));
        break;
    case ROOK :
        threatened = rAttacks;
        break;
    case CANNON :
        threatened = cAttacks;
        break;

    default :
        threatened = attacks_bb(type_of(pc), s, occupied);
    }

    threatened &= occupied;

    while (threatened)
    {
        Square threatenedSq = pop_lsb(threatened);
        Piece  threatenedPc = piece_on(threatenedSq);

        assert(threatenedSq != s);
        assert(threatenedPc);

        add_dirty_threat(dts, putPiece, pc, threatenedPc, s, threatenedSq);
    }

    // Incoming threats
    Bitboard incoming_threats = (attacks_bb(PAWN_TO, s, WHITE) & pieces(WHITE, PAWN))
                              | (attacks_bb(PAWN_TO, s, BLACK) & pieces(BLACK, PAWN))
                              | (attacks_bb(KNIGHT_TO, s, occupied) & pieces(KNIGHT))
                              | (attacks_bb(BISHOP, s, occupied) & pieces(BISHOP))
                              | (attacks_bb(ADVISOR, s) & pieces(ADVISOR))
                              | (attacks_bb(KING, s) & pieces(KING));

    // Discovered threats
    if constexpr (ComputeRay)
    {
        // Rooks threat pieces on the other side
        Bitboard sliders = rAttacks & pieces(ROOK);
        while (sliders)
        {
            Square sliderSq = pop_lsb(sliders);
            Piece  slider   = piece_on(sliderSq);

            const Bitboard discovered = ray_pass_bb(sliderSq, s) & rAttacks & occupied;

            assert(!more_than_one(discovered));
            if (discovered)
            {
                const Square threatenedSq = lsb(discovered);
                const Piece  threatenedPc = piece_on(threatenedSq);
                add_dirty_threat(dts, !putPiece, slider, threatenedPc, sliderSq, threatenedSq);
            }

            add_dirty_threat(dts, putPiece, slider, pc, sliderSq, s);
        }
        // Cannons threat pieces on the other side
        sliders = cAttacks & pieces(CANNON);
        while (sliders)
        {
            Square sliderSq = pop_lsb(sliders);
            Piece  slider   = piece_on(sliderSq);

            // Jumping over the first piece before 's'
            const Bitboard discovered = ray_pass_bb(sliderSq, s) & rAttacks & occupied;

            assert(!more_than_one(discovered));
            if (discovered)
            {
                const Square threatenedSq = lsb(discovered);
                const Piece  threatenedPc = piece_on(threatenedSq);
                add_dirty_threat(dts, !putPiece, slider, threatenedPc, sliderSq, threatenedSq);
            }

            add_dirty_threat(dts, putPiece, slider, pc, sliderSq, s);
        }
        sliders = rAttacks & pieces(CANNON);
        while (sliders)
        {
            Square sliderSq = pop_lsb(sliders);
            Piece  slider   = piece_on(sliderSq);

            // Jumping over 's'
            Bitboard discovered = ray_pass_bb(sliderSq, s) & rAttacks & occupied;

            assert(!more_than_one(discovered));
            if (discovered)
            {
                const Square threatenedSq = lsb(discovered);
                const Piece  threatenedPc = piece_on(threatenedSq);
                add_dirty_threat(dts, putPiece, slider, threatenedPc, sliderSq, threatenedSq);
            }

            // Jumping over the first piece after 's'
            discovered = ray_pass_bb(sliderSq, s) & cAttacks & occupied;

            assert(!more_than_one(discovered));
            if (discovered)
            {
                const Square threatenedSq = lsb(discovered);
                const Piece  threatenedPc = piece_on(threatenedSq);
                add_dirty_threat(dts, !putPiece, slider, threatenedPc, sliderSq, threatenedSq);
            }
        }

        // Knights with 's' in between threat pieces on the other side
        // Bishops with 's' in between threat pieces on the other side
        Bitboard leapers = (unconstrained_attacks_bb(KING, s) & pieces(KNIGHT))
                         | (unconstrained_attacks_bb(ADVISOR, s) & pieces(BISHOP));
        while (leapers)
        {
            Square leaperSq = pop_lsb(leapers);
            Piece  leaper   = piece_on(leaperSq);

            Bitboard discovered = leaper_pass_bb(leaperSq, s) & occupied;

            assert(type_of(leaper) == KNIGHT ? popcount(discovered) <= 2
                                             : !more_than_one(discovered));
            while (discovered)
            {
                const Square threatenedSq = pop_lsb(discovered);
                const Piece  threatenedPc = piece_on(threatenedSq);
                add_dirty_threat(dts, !putPiece, leaper, threatenedPc, leaperSq, threatenedSq);
            }
        }
    }
    else
        incoming_threats |= (rAttacks & pieces(ROOK)) | (cAttacks & pieces(CANNON));

    while (incoming_threats)
    {
        Square srcSq = pop_lsb(incoming_threats);
        Piece  srcPc = piece_on(srcSq);

        assert(srcSq != s);
        assert(srcPc != NO_PIECE);

        add_dirty_threat(dts, putPiece, srcPc, pc, srcSq, s);
    }
}

Key Position::prefetch_key(Move m) const {
    Square from     = m.from_sq();
    Square to       = m.to_sq();
    Piece  pc       = piece_on(from);
    Piece  captured = piece_on(to);
    Key    k        = st->key ^ Zobrist::side;

    k ^= Zobrist::psq[captured][to] ^ Zobrist::psq[pc][to] ^ Zobrist::psq[pc][from];

    if (captured)
        return k;

    return adjust_key60<true>(k);
}


// Used to do a "null move": it flips
// the side to move without executing any move on the board.
void Position::do_null_move(StateInfo& newSt) {

    assert(!checkers());
    assert(&newSt != st);

    // Update the bloom filter
    ++filter[st->key];

    std::memcpy(&newSt, st, sizeof(StateInfo));

    newSt.previous = st;
    st             = &newSt;

    st->key ^= Zobrist::side;

    st->pliesFromNull = 0;

    st->capturedPiece = NO_PIECE;
    st->skyCapturedId = 0;
    sky_invalidate(st);

    sideToMove = ~sideToMove;

    set_extra_bitboards();

    assert(pos_is_ok());
}


// Must be used to undo a "null move"
void Position::undo_null_move() {

    assert(!checkers());

    st         = st->previous;
    sideToMove = ~sideToMove;

    // Update the bloom filter
    --filter[st->key];
}


// Tests if the SEE (Static Exchange Evaluation)
// value of the move is greater or equal to the given threshold. We'll use an
// algorithm similar to alpha-beta pruning with a null window.
bool Position::see_ge(Move m, int threshold) const {

    assert(m.is_ok());

    Square from = m.from_sq(), to = m.to_sq();

    assert(piece_on(from) != NO_PIECE);

    int swap = PieceValue[piece_on(to)] - threshold;
    if (swap < 0)
        return false;

    swap = PieceValue[piece_on(from)] - swap;
    if (swap <= 0)
        return true;

    assert(color_of(piece_on(from)) == sideToMove);
    Bitboard occupied  = pieces() ^ from ^ to;  // xoring to is important for pinned piece logic
    Color    stm       = sideToMove;
    Bitboard attackers = attackers_to(to, occupied);

    // Flying general
    bool kingAttacks = attackers & pieces(KING);
    if (kingAttacks)
        attackers |= attacks_bb(ROOK, to, occupied) & pieces(KING);

    Bitboard nonCannons = attackers & ~pieces(CANNON);
    Bitboard cannons    = attackers & pieces(CANNON);
    Bitboard stmAttackers, bb;
    int      res = 1;

    while (true)
    {
        stm = ~stm;
        attackers &= occupied;

        // If stm has no more attackers then give up: stm loses
        if (!(stmAttackers = attackers & pieces(stm)))
            break;

        // Don't allow pinned pieces to attack as long as there are
        // pinners on their original square.
        if (pinners(~stm) & occupied)
        {
            stmAttackers &= ~blockers_for_king(stm);

            if (!stmAttackers)
                break;
        }

        res ^= 1;

        // Locate and remove the next least valuable attacker, and add to the
        // bitboard 'attackers' any protential attackers when it is removed.
        if ((bb = stmAttackers & pieces(PAWN)))
        {
            if ((swap = PawnValue - swap) < res)
                break;
            occupied ^= least_significant_square_bb(bb);

            nonCannons |=
              attacks_bb(ROOK, to, occupied) & (kingAttacks ? pieces(KING, ROOK) : pieces(ROOK));
            cannons   = attacks_bb(CANNON, to, occupied) & pieces(CANNON);
            attackers = nonCannons | cannons;
        }

        else if ((bb = stmAttackers & pieces(BISHOP)))
        {
            if ((swap = BishopValue - swap) < res)
                break;
            occupied ^= least_significant_square_bb(bb);
        }

        else if ((bb = stmAttackers & pieces(ADVISOR)))
        {
            if ((swap = AdvisorValue - swap) < res)
                break;
            occupied ^= least_significant_square_bb(bb);

            nonCannons |= attacks_bb(KNIGHT_TO, to, occupied) & pieces(KNIGHT);
            attackers = nonCannons | cannons;
        }

        else if ((bb = stmAttackers & pieces(CANNON)))
        {
            if ((swap = CannonValue - swap) < res)
                break;
            occupied ^= least_significant_square_bb(bb);

            cannons   = attacks_bb(CANNON, to, occupied) & pieces(CANNON);
            attackers = nonCannons | cannons;
        }

        else if ((bb = stmAttackers & pieces(KNIGHT)))
        {
            if ((swap = KnightValue - swap) < res)
                break;
            occupied ^= least_significant_square_bb(bb);
        }

        else if ((bb = stmAttackers & pieces(ROOK)))
        {
            swap = RookValue - swap;
            occupied ^= least_significant_square_bb(bb);

            nonCannons |=
              attacks_bb(ROOK, to, occupied) & (kingAttacks ? pieces(KING, ROOK) : pieces(ROOK));
            cannons   = attacks_bb(CANNON, to, occupied) & pieces(CANNON);
            attackers = nonCannons | cannons;
        }

        else  // KING
              // If we "capture" with the king but the opponent still has attackers,
              // reverse the result.
            return (attackers & ~pieces(stm)) ? res ^ 1 : res;
    }

    return bool(res);
}


// A lighter version of do_move(), used in chasing detection
std::pair<Piece, int> Position::do_move(Move m) {

    assert(capture(m));

    Square from     = m.from_sq();
    Square to       = m.to_sq();
    Piece  captured = piece_on(to);
    int    id       = idBoard[to];

    // Update id board
    idBoard[to]   = idBoard[from];
    idBoard[from] = 0;

    // Update board and piece lists
    remove_piece(to);
    move_piece(from, to);

    sideToMove = ~sideToMove;

    return {captured, id};
}


// A lighter version of undo_move(), used in chasing detection
void Position::undo_move(Move m, Piece captured, int id) {

    sideToMove = ~sideToMove;

    Square from = m.from_sq();
    Square to   = m.to_sq();

    // Put back id board
    idBoard[from] = idBoard[to];
    idBoard[to]   = id;

    move_piece(to, from);  // Put the piece back at the source square

    if (captured)
        put_piece(captured, to);  // Restore the captured piece
}


// Tests whether a pseudo-legal move is chase legal
bool Position::chase_legal(Move m, Bitboard b) const {

    assert(m.is_ok());

    Color    us       = sideToMove;
    Square   from     = m.from_sq();
    Square   to       = m.to_sq();
    Bitboard occupied = (pieces() ^ from) | to;

    assert(color_of(moved_piece(m)) == us);
    assert(piece_on(king_square(us)) == make_piece(us, KING));

    // If the moving piece is a king, check whether the destination
    // square is not under new attack after the move.
    if (type_of(piece_on(from)) == KING)
        return !(checkers_to(~us, to, occupied) & ~b);

    // A non-king move is chase legal if the king is not under new attack after the move.
    return !((checkers_to(~us, king_square(us), occupied) & ~square_bb(to)) & ~b);
}


// Calculates the exact SkyRule attacker -> victim relation for a given color.
// Unlike chased(), this keeps the attacker's identity. The supplied SkyRule
// binary stores both the victim union and the chaser union for each historical move.
// Shares the same chase_legal(m, b) primitive and the same checkUs/checkThem
// semantics as chased(), so the "常捉无根子" detection stays consistent across rules.
SkyChaseMap Position::sky_chased(Color c) {

    SkyChaseMap chase;

    // Checkers bitboard for both sides, computed before the sideToMove swap so
    // that the semantics match chased(): checkUs is c's checker state, checkThem
    // is c's checking state. Passed to the shared chase_legal(m, b) so it only
    // flags moves that create NEW attacks on the king.
    Bitboard checkUs   = st->checkersBB;
    Bitboard checkThem = checkers_to(sideToMove, king_square(~sideToMove));
    if (c != sideToMove)
        std::swap(checkUs, checkThem);

    std::swap(c, sideToMove);

    Bitboard attackers = pieces(sideToMove) ^ pieces(sideToMove, KING, PAWN);
    while (attackers)
    {
        Square    from         = pop_lsb(attackers);
        int       attackerId   = idBoard[from];
        PieceType attackerType = type_of(piece_on(from));
        Bitboard  attacks      = attacks_bb(attackerType, from, pieces());

        // 天天象棋棋规【一】4：受牵制的子捉其他子不算捉。吃掉牵制子本身不会暴露
        // 帅（将），所以被牵子仍可捉牵制它的子（例如绊马腿的车捉该马）。
        // 【一】2 / 【二】2：未过河卒不算，过河卒算；帅（将）不算被捉子。
        if (blockers_for_king(sideToMove) & from)
            attacks &= pinners(~sideToMove) & ~pieces(KING);
        else
            attacks &= (pieces(~sideToMove) ^ pieces(~sideToMove, KING, PAWN))
                     | (pieces(~sideToMove, PAWN) & HalfBB[sideToMove]);

        // 天天象棋棋规【三】1：除车、兵外其他子捉车，无论车是否有根，算捉。
        // （车捉车走同类子路径；帅兵不在 attackers 之内。）
        Bitboard candidates = attackerType != ROOK ? attacks & pieces(~sideToMove, ROOK) : 0;

        attacks ^= candidates;
        while (candidates)
        {
            Square to = pop_lsb(candidates);
            if (chase_legal(Move(from, to), checkUs))
                chase.add(idBoard[to], attackerId);
        }

        while (attacks)
        {
            Square to = pop_lsb(attacks);
            Move   m(from, to);
            if (!chase_legal(m, checkUs))
                continue;

            // Recapturers after the capture, computed on the current board with the
            // post-capture occupancy: the victim never attacks its own square and the
            // mover is filtered out by colour, so this equals attackers_to(to) after
            // do_move(m). Only when somebody can recapture do we need the real
            // post-capture position for chase_legal().
            bool     trueChase  = true;
            Bitboard recaptures = attackers_to(to, (pieces() ^ from) | to) & pieces(~sideToMove);
            if (recaptures)
            {
                const auto [captured, id] = do_move(m);
                while (recaptures)
                {
                    Square sq = pop_lsb(recaptures);
                    if (chase_legal(Move(sq, to), checkThem))
                    {
                        trueChase = false;
                        break;
                    }
                }
                undo_move(m, captured, id);
            }

            if (!trueChase)
                continue;

            if (attackerType == type_of(piece_on(to)))
            {
                sideToMove = ~sideToMove;
                if ((attackerType == KNIGHT && ((between_bb(from, to) ^ to) & pieces()))
                    || !chase_legal(Move(to, from), checkThem))
                    chase.add(idBoard[to], attackerId);
                sideToMove = ~sideToMove;
            }
            else
                chase.add(idBoard[to], attackerId);
        }
    }

    std::swap(c, sideToMove);
    return chase;
}


// Calculates the chase information for a given color.
// Returns a ChaseMap that encodes (victim, attacker) id pairs, so that the
// perpetual-chase accumulation in detect_chases can correctly verify that the
// SAME attacker keeps chasing the SAME victim across the repetition cycle.
// This is the shared "常捉无根子" detector used by AsianRule, SkyRule and YitianRule;
// each rule still applies its own scoring on top of the resulting victim mask.
ChaseMap Position::chased(Color c) {

    ChaseMap chase;

    // No early return on the root state (st->move == none): the standing attacks of
    // the root position are the "before" set of the first move of a cycle that
    // includes the root. Returning an empty map there made every attack of that
    // first move look newly created (24.3: a chase is what the move creates).

    // Checkers bitboard for both sides. checkUs is c's checker state, checkThem
    // is c's checking state. Passed to the shared chase_legal(m, b) so it only
    // flags moves that create NEW attacks on the king.
    Bitboard checkUs   = st->checkersBB;
    Bitboard checkThem = checkers_to(sideToMove, king_square(~sideToMove));
    if (c != sideToMove)
        std::swap(checkUs, checkThem);

    std::swap(c, sideToMove);

    // King and pawn can legally perpetual chase.
    Bitboard attackers = pieces(sideToMove) ^ pieces(sideToMove, KING, PAWN);
    while (attackers)
    {
        Square    from         = pop_lsb(attackers);
        PieceType attackerType = type_of(piece_on(from));
        Bitboard  attacks      = attacks_bb(attackerType, from, pieces());

        // Restrict to pinners if pinned, otherwise exclude attacks on unpromoted pawns and checks.
        // 天天象棋棋规【一】4：受牵制的子捉其他子不算捉。吃掉牵制子本身不会暴露
        // 帅（将），所以被牵子仍可捉牵制它的子（例如绊马腿的车捉该马）。
        // 【一】2 / 【二】2：未过河卒不算，过河卒算；帅（将）不算被捉子。
        if (blockers_for_king(sideToMove) & from)
            attacks &= pinners(~sideToMove) & ~pieces(KING);
        else
            attacks &= (pieces(~sideToMove) ^ pieces(~sideToMove, KING, PAWN))
                     | (pieces(~sideToMove, PAWN) & HalfBB[sideToMove]);

        // Rooks chased regardless of protection.
        // ChineseRule（天天象棋棋规【三】1）：除车、兵外其他子捉车，无论车是否有根，算捉。
        // AsianRule（亚象联棋例总纲 6、细则 15/20/21/37）/ YitianRule（弈天规则 14）：
        // 只有马或炮捉有根车仍算捉；士、象捉有真根之车属“长捉真根子作和”。
        // （车捉车走同类子路径；帅兵不在 attackers 之内。）
        Bitboard candidates =
          (attackerType == KNIGHT || attackerType == CANNON
           || (attackerType != ROOK && RuleConfig::repetitionRule == RuleConfig::RepetitionRule::CHINESE))
            ? attacks & pieces(~sideToMove, ROOK)
            : 0;

        attacks ^= candidates;
        while (candidates)
        {
            Square to = pop_lsb(candidates);
            if (chase_legal(Move(from, to), checkUs))
                chase |= make_chase(idBoard[to], idBoard[from]);
        }

        // Attacks against potentially unprotected pieces.
        while (attacks)
        {
            Square to = pop_lsb(attacks);
            Move   m  = Move(from, to);

            if (chase_legal(m, checkUs))
            {
                // See sky_chased(): only enter the real post-capture position when
                // the victim's side has at least one potential recapturer.
                bool     trueChase  = true;
                Bitboard recaptures = attackers_to(to, (pieces() ^ from) | to) & pieces(~sideToMove);
                if (recaptures)
                {
                    const auto [captured, id] = do_move(m);
                    while (recaptures)
                    {
                        Square s = pop_lsb(recaptures);
                        if (chase_legal(Move(s, to), checkThem))
                        {
                            trueChase = false;
                            break;
                        }
                    }
                    undo_move(m, captured, id);
                }

                if (trueChase)
                {
                    // Exclude mutual/symmetric attacks except pins.
                    if (attackerType == type_of(piece_on(to)))
                    {
                        sideToMove = ~sideToMove;
                        if ((attackerType == KNIGHT && ((between_bb(from, to) ^ to) & pieces()))
                            || !chase_legal(Move(to, from), checkThem))
                            chase |= make_chase(idBoard[to], idBoard[from]);
                        sideToMove = ~sideToMove;
                    }
                    else
                        chase |= make_chase(idBoard[to], idBoard[from]);
                }
            }
        }
    }

    std::swap(c, sideToMove);

    return chase;
}


// Calculates whether the side to move has a forced checking mate threat within the configured depth.
// This is used only by ChineseRule.
bool Position::has_mate_threat(Depth d) {

    if (d == -1)
    {
        StateInfo nullSt;
        do_null_move(nullSt);
        bool mateThreat = has_mate_threat(0);
        undo_null_move();
        return mateThreat;
    }

    if (d >= RuleConfig::mateThreatDepth)
        return false;

    StateInfo tempSt[2];
    for (const auto& check : MoveList<ALL>(*this))
    {
        if (!gives_check(check))
            continue;

        do_move(check, tempSt[0]);
        bool solvable = false;

        for (const auto& evasion : MoveList<ALL>(*this))
        {
            do_move(evasion, tempSt[1]);
            solvable = !has_mate_threat(d + 1);
            undo_move(evasion);
            if (solvable)
                break;
        }

        undo_move(check);
        if (!solvable)
            return true;
    }

    return false;
}


// Fills the SkyRule state carried by each move while rolling the current line back.
// Check and chase are classified as mutually exclusive move types; checking moves use
// victims=0xffff and keep checker identities, while non-checking moves store the exact
// newly-created victim/chaser relation. The information depends only on the two
// positions around the move and on the persistent piece identities, so a state that
// has already been computed (by any thread) is skipped and only rolled back over.
// This runs on a scratch copy of the position: the board is rolled back, the shared
// StateInfo chain receives the results.
void Position::set_sky_info(int d) {

    for (int i = 0; i < d && st && st->previous; ++i)
    {
        StateInfo* cur = st;
        if (cur->capturedPiece != NO_PIECE)
            break;

        if (sky_cached(cur))
        {
            undo_move(cur->move, NO_PIECE, 0);
            st = cur->previous;
            continue;
        }

        const Color mover = ~sideToMove;

        // In the target SkyRule, a checking move is not simultaneously counted as a chase.
        if (cur->checkersBB)
        {
            u16      checkers = 0;
            Bitboard checks   = cur->checkersBB;
            while (checks)
                checkers |= u16(1u << idBoard[pop_lsb(checks)]);

            undo_move(cur->move, NO_PIECE, 0);
            st = cur->previous;
            sky_publish(cur, 0xFFFF, checkers, 0);
            continue;
        }

        // Mate-threat ("kill") recursion is deliberately absent for SkyRule.
        SkyChaseMap after = sky_chased(mover);
        undo_move(cur->move, NO_PIECE, 0);
        st = cur->previous;
        SkyChaseMap before = sky_chased(mover);
        SkyChaseMap exact  = after.exact_diff(before);
        sky_publish(cur, exact.victims(), 0, exact.chasers());
    }
}


// SkyRule repetition classifier. A and B are the two alternating movers in the
// repetition cycle. The verdict depends only on the moves inside the cycle, so the
// same cycle is always judged the same way regardless of how it was entered.
//
// SkyRule priorities (a cycle that repeats is treated as perpetual, i.e. every
// per-side move limit below is eventually exceeded):
//   1. Check/chase alternation (一将一捉 / 一捉一将) is forbidden in every case: a side
//      whose cycle mixes checks with chasing moves changes, whatever the opponent
//      does (idle, chase, or block-and-chase) and even if the chased pieces vary.
//   2. Both sides alternate check/chase: one piece is limited to 12 moves, more
//      than one piece to 18 moves; the side with the tighter limit changes,
//      equal limits are a draw.
//   3. One side keeps a common victim, the other does not: the chaser changes.
//   4. Both sides only chase: draw (one or more pieces chasing one piece share
//      the same 6-move limit).
// Pure perpetual check on one or both sides is handled by rule_judge() before
// this function is called ("一方长将，一方长捉，长将方禁招").
Value Position::detect_sky_cycle(int d, int ply) {

    if (d < 4 || !st)
        return VALUE_DRAW;

    const Color currentSide = sideToMove;

    // Collect the cycle states (most recent first) without touching the heap in the
    // common case, and find out whether any of them still needs its Sky info.
    StateInfo*              local[256];
    std::vector<StateInfo*> heap;
    StateInfo**             q = local;
    if (d > int(sizeof(local) / sizeof(local[0])))
    {
        heap.resize(d);
        q = heap.data();
    }

    int  n         = 0;
    bool allCached = true;
    for (StateInfo* p = st; p && p->previous && n < d; p = p->previous)
    {
        if (p->capturedPiece != NO_PIECE)
            break;
        q[n++] = p;
        allCached &= sky_cached(p);
    }
    if (n < d)
        return VALUE_DRAW;

    // Roll the cycle back on a scratch copy only for the states not yet computed.
    // The board copy stops at the bloom filter; the StateInfo chain is shared.
    if (!allCached)
    {
        Position scratch;
        std::memcpy((void*) &scratch, (const void*) this, offsetof(Position, filter));
        std::memcpy((void*) scratch.idBoard, (const void*) idBoard, sizeof(idBoard));
        scratch.set_sky_info(d);
    }

    auto checked  = [](const StateInfo* s) { return bool(s->checkersBB); };
    auto loss_for = [&](Color offender) {
        return offender == currentSide ? mated_in(ply) : mate_in(ply);
    };

    // A made moves 0,2,4,... and is the opponent of the side to move now.
    const Color AColor = ~currentSide;
    const Color BColor = currentSide;

    const StateInfo* s0 = q[0];
    const StateInfo* s1 = q[1];
    const StateInfo* s2 = q[2];
    const StateInfo* s3 = q[3];

    const bool splitA     = s0->skyVictims && s2->skyVictims && !(s0->skyVictims & s2->skyVictims);
    const bool splitB     = s1->skyVictims && s3->skyVictims && !(s1->skyVictims & s3->skyVictims);
    const bool checkIdleA = (checked(s0) && s2->skyVictims == 0)
                         || (checked(s2) && s0->skyVictims == 0);
    const bool checkIdleB = (checked(s1) && s3->skyVictims == 0)
                         || (checked(s3) && s1->skyVictims == 0);

    // Per side over the whole cycle: common victims (a check counts as attacking
    // everything), whether any move is a check, whether every move is offensive
    // (a check or a chase of anything), and the attacking identities.
    u16  common[2]     = {0xFFFF, 0xFFFF};
    bool anyCheck[2]   = {false, false};
    bool allOffend[2]  = {true, true};
    u16  identities[2] = {0, 0};
    for (int i = 0; i < d; ++i)
    {
        const StateInfo* x    = q[i];
        const int        side = i & 1;  // 0 = A, 1 = B
        common[side] &= x->skyVictims;
        if (checked(x))
        {
            anyCheck[side] = true;
            identities[side] |= x->skyCheckers;
        }
        else
        {
            allOffend[side] = allOffend[side] && x->skyVictims;
            identities[side] |= x->skyChasers;
        }
    }
    const u16 A = common[0];
    const u16 B = common[1];

    // 1. Check/chase alternation is forbidden in every case.
    const bool mixedA = anyCheck[0] && allOffend[0];
    const bool mixedB = anyCheck[1] && allOffend[1];
    if (mixedA != mixedB)
        return loss_for(mixedA ? AColor : BColor);

    // 2. Check/chase alternation on both sides: 1 piece -> 12 moves, more -> 18 moves.
    if (mixedA)
    {
        auto multi = [](u16 ids) { return bool(ids & u16(ids - 1)); };
        const bool multiA = multi(identities[0]);
        const bool multiB = multi(identities[1]);
        if (multiA != multiB)
            return loss_for(multiA ? BColor : AColor);
        return VALUE_DRAW;
    }

    // No common victim on either side. The target has one Sky-only exception for a split
    // chase against check/idle alternation; a king move is explicitly exempt.
    if (!A && !B)
    {
        auto current_piece_type = [&](const StateInfo* sm) {
            Move m = sm->move;
            if (!m.is_ok())
                return NO_PIECE_TYPE;
            Piece pc = piece_on(m.to_sq());
            return pc == NO_PIECE ? NO_PIECE_TYPE : type_of(pc);
        };

        if (splitA && checkIdleB && current_piece_type(s0) != KING)
            return loss_for(AColor);
        if (splitB && checkIdleA && current_piece_type(s1) != KING)
            return loss_for(BColor);
        return VALUE_DRAW;
    }

    // 3. Exactly one side keeps a common victim throughout the cycle: that side changes.
    if (A && !B)
        return loss_for(AColor);
    if (!A && B)
        return loss_for(BColor);

    // 4. Pure chase against pure chase.
    return VALUE_DRAW;
}


// Detects chases from state st - d to state st.
Value Position::detect_chases(int d, int ply) {

    using RR = RuleConfig::RepetitionRule;

    // AllowChase only forbids perpetual check; this function is called for a non-checking cycle.
    // NoJudgement does not assign blame for a cycle.
    if (RuleConfig::repetitionRule == RR::ALLOW_CHASE
        || RuleConfig::repetitionRule == RR::NO_JUDGEMENT)
        return VALUE_DRAW;

    // Piece identities are persistent (assigned in set(), moved by do_move()).
    Color us = sideToMove, them = ~us;

    // ComputerRule keeps the current strict detector.
    if (RuleConfig::repetitionRule == RR::COMPUTER)
    {
        u16 chase[COLOR_NB] = {0xFFFF, 0xFFFF};
        for (int i = 0; i < d; ++i)
        {
            if (st->checkersBB)
                return VALUE_DRAW;
            else if (!chase[~sideToMove])
            {
                if (!chase[sideToMove])
                    break;
                undo_move(st->move, st->capturedPiece);
                st = st->previous;
            }
            else
            {
                u16 after = u16(chased(~sideToMove));
                undo_move(st->move, st->capturedPiece);
                st = st->previous;
                chase[sideToMove] &= after & ~u16(chased(sideToMove));
            }
        }

        return bool(chase[us]) ^ bool(chase[them]) ? chase[us] ? mated_in(ply) : mate_in(ply)
                                                   : VALUE_DRAW;
    }

    // Asian/Chinese/Sky/Yitian use the 2-fold chase classifier. ChineseRule and
    // SkyRule share the "all pieces simultaneously" semantics. The chase diff is
    // computed with ChaseMap (victim, attacker) pairs so that a victim chased by
    // a different attacker is not confused with a continued chase by the original
    // attacker (the "带根长捉" fix shared by all three rules). The accumulated
    // victim mask is then consumed by each rule's own scoring below.
    const bool chineseLike = RuleConfig::chinese_like();
    const bool chineseRule = RuleConfig::repetitionRule == RR::CHINESE;

    // ChineseRule: 中国象棋协会《象棋竞赛规则》2020 版第 25~26 条的裁决框架，
    // 但"捉"统一采用天天象棋棋规（见 chased()）：
    //   24.13  长将、长杀、长捉、一将一杀、一将一捉、一杀一捉为禁止着法；
    //          一方只要有一着闲着即为允许着法。
    //   25.1   单方长将任何情况须变着（rule_judge() 已先行裁定）。
    //   25.2   双方允许 → 和。  25.3  一方禁止一方允许 → 禁止方变着。
    //   25.4   双方均禁止 → 26.9。因为天天规则下成立的捉只有捉车、捉无根(假根)子，
    //          26.9.1 列举的"重"禁着覆盖所有可能的禁着，双方对等 → 26.9.4 和。
    //   26.1.2 走动帅应将而产生的捉、杀按闲处理。
    //   天天【一】1：一子或多子连续分捉多子不算捉 —— 本方所有捉着必须有共同的被捉子
    //          （victim id 交集非空），否则该方按闲处理。
    if (chineseRule)
    {
        bool hasIdle[COLOR_NB] = {false, false};
        u16  victims[COLOR_NB] = {0xFFFF, 0xFFFF};  // 本方捉着的共同被捉子

        for (int i = 0; i < d; ++i)
        {
            StateInfo*  cur   = st;
            const Color mover = ~sideToMove;

            if (hasIdle[WHITE] && hasIdle[BLACK])
                break;

            auto step_back = [&]() {
                undo_move(cur->move, cur->capturedPiece);
                st = cur->previous;
            };

            // A check is a forbidden move by itself; a side already known to have
            // played an idle move is an allowed side, nothing more to learn about it.
            if (cur->checkersBB || hasIdle[mover])
            {
                step_back();
                continue;
            }

            // 26.1.2: the king stepping out of check -> idle whatever it uncovers.
            if (cur->previous->checkersBB && type_of(piece_on(cur->move.to_sq())) == KING)
            {
                hasIdle[mover] = true;
                step_back();
                continue;
            }

            ChaseMap   after = chased(mover);
            const bool kill  = RuleConfig::mateThreatDepth > 0 && has_mate_threat();

            step_back();

            if (kill)
                continue;  // 杀（含杀兼捉）: forbidden, nothing more to record

            ChaseMap before = chased(mover);
            ChaseMap fresh  = after;
            (void) (fresh & before);  // fresh = after - before: newly created chases

            u16 freshVictims = 0;
            for (int v = 0; v < 16; ++v)
                if (fresh.victims[v])
                    freshVictims |= u16(1) << v;

            victims[mover] &= freshVictims;
            if (!victims[mover])
                hasIdle[mover] = true;  // 闲着，或分捉多子（不算捉）
        }

        const bool forbUs = !hasIdle[us], forbThem = !hasIdle[them];
        if (forbUs != forbThem)
            return forbUs ? mated_in(ply) : mate_in(ply);  // 25.3
        return VALUE_DRAW;                                 // 25.2 / 26.9.4
    }

    u16      rooks[COLOR_NB] = {0xFFFF, 0xFFFF};
    u16      chase[COLOR_NB] = {0xFFFF, 0xFFFF};  // u16 victim-mask intersection accumulation
    ChaseMap newChase[COLOR_NB];                  // ChaseMap (victim, attacker) per side
    newChase[us] = chased(us);

    // AsianRule / YitianRule: 一将一捉 (check/chase alternation) is an allowed
    // sequence, so a check simply ends that side's perpetual chase (chase mask
    // cleared) and the side counts as allowed; the usual scoring below then gives
    // a draw against an idle or alternating opponent and a loss for a perpetual
    // chaser. Only SkyRule forbids the alternation, in detect_sky_cycle().
    // 亚象联棋例总纲 2 / 细则 12：一照一捉作和；细则 18（图三十七）、23（图五十）：
    // 对方一照一捉而己方长捉，长捉方不变作负。弈天规则 19、24 相同。
    for (int i = 0; i < d; ++i)
    {
        const Color mover = ~sideToMove;

        if (!chase[mover])
        {
            if (!chase[sideToMove])
                break;
            undo_move(st->move, st->capturedPiece);
            st = st->previous;
        }
        else if (st->checkersBB
                 || (chineseRule && RuleConfig::mateThreatDepth > 0 && has_mate_threat()))
        {
            // In Chinese-like rules, check/mate-threat is treated as chasing all pieces.
            chase[mover] &= chineseLike ? 0xFFFF : 0;
            rooks[mover] = 0;
            undo_move(st->move, st->capturedPiece);
            st = st->previous;
        }
        else
        {
            ChaseMap oldChase = chased(mover);
            u16      flag     = 0;

            // Asian-style special case: a rook pinned by a knight may itself be the chased piece.
            if (!chineseLike && rooks[~sideToMove]
                && (blockers_for_king(sideToMove) & pieces(sideToMove, ROOK)))
            {
                Bitboard knights = pinners(~sideToMove) & pieces(KNIGHT);
                while (knights)
                {
                    Square   s = pop_lsb(knights);
                    Bitboard b = between_bb(king_square(sideToMove), s) ^ s;
                    s          = pop_lsb(b);
                    if (piece_on(s) == make_piece(sideToMove, ROOK))
                        flag |= 1 << idBoard[s];
                }
            }

            undo_move(st->move, st->capturedPiece);
            st = st->previous;

            // ChaseMap diff (victim, attacker): newly created chase pairs for this move.
            // operator& is an in-place set difference; the (void) cast keeps the side effect
            // (chases becomes oldChase - newChase) and discards the returned reference.
            ChaseMap chases = oldChase;
            (void)(chases & newChase[sideToMove]);
            u16      chasesU16    = u16(chases);  // collapse to victim mask for accumulation
            newChase[sideToMove] = chased(sideToMove);

            if (chineseLike)
            {
                // Chinese-like rules recompute the diff against the updated newChase.
                chases = oldChase;
                (void)(chases & newChase[sideToMove]);
                chasesU16 = u16(chases);
            }
            else
            {
                // AsianRule / YitianRule: a chase pair must also be created by this move
                // (absent before it), not only end on the opponent's reply.
                // 弈天规则 13：走子前不存在“捉”的状态，而走子后才造成“捉”的状态；
                // 亚象联“长捉”：甲方连走捉着而乙方被捉之子每着逃避。
                // An attack the opponent walked into (献着) is therefore not a chase.
                (void)(chases & newChase[sideToMove]);
                chasesU16 = u16(chases);
                if (i == d - 2)
                    chasesU16 &= ~u16(newChase[sideToMove]);
            }

            rooks[sideToMove] &= chasesU16 & flag;
            chase[sideToMove] &= chineseLike && chasesU16 ? 0xFFFF : chasesU16;
        }
    }

    if ((!chase[us] && !chase[them]) || (rooks[us] && rooks[them]))
        return VALUE_DRAW;
    if (rooks[us])
        return mated_in(ply);
    if (rooks[them])
        return mate_in(ply);

    return !chase[us] ? mate_in(ply) : !chase[them] ? mated_in(ply) : VALUE_DRAW;
}


// Tests whether the position may end the game by rule 60, insufficient material, draw repetition,
// perpetual check repetition or perpetual chase repetition that allows a player to claim a game result.
bool Position::rule_judge(Value& result, int ply) {

    using RR = RuleConfig::RepetitionRule;
    using DR = RuleConfig::DrawRule;

    auto apply_draw_rule = [&](bool repetition) {
        if (result != VALUE_DRAW)
            return;

        Color winner = COLOR_NB;
        if (RuleConfig::drawRule == DR::BLACK_WIN
            || (repetition && RuleConfig::drawRule == DR::REP_BLACK_WIN))
            winner = BLACK;
        else if (RuleConfig::drawRule == DR::RED_WIN
                 || (repetition && RuleConfig::drawRule == DR::REP_RED_WIN))
            winner = WHITE;  // WHITE is Red in Pikafish's Xiangqi representation.

        if (winner != COLOR_NB)
            result = winner == sideToMove ? mate_in(ply) : mated_in(ply);
    };

    // Restore rule 60 by adding back the checks. Captures/null moves still bound the
    // repetition history even when the natural-move draw itself is disabled.
    int end = std::min(st->rule60 + std::max(0, st->check10[WHITE] - 10)
                         + std::max(0, st->check10[BLACK] - 10),
                       st->pliesFromNull);

    if (end >= 4 && filter[st->key] >= 1)
    {
        int        cnt       = 0;
        StateInfo* stp       = st->previous->previous;
        bool       checkThem = st->checkersBB && stp->checkersBB;
        bool       checkUs   = st->previous->checkersBB && stp->previous->checkersBB;

        for (int i = 4; i <= end; i += 2)
        {
            stp = stp->previous->previous;
            checkThem &= bool(stp->checkersBB);

            if (stp->key == st->key)
            {
                ++cnt;

                const bool computerReady =
                  RuleConfig::repetitionRule == RR::COMPUTER && (cnt == 2 || ply > i);
                const bool legacyReady =
                  RuleConfig::repetitionRule != RR::COMPUTER && cnt >= 1;

                if (computerReady || legacyReady)
                {
                    if (RuleConfig::repetitionRule == RR::NO_JUDGEMENT)
                        result = VALUE_DRAW;
                    else if (!checkThem && !checkUs)
                    {
                        if (RuleConfig::repetitionRule == RR::SKY)
                            // Reads the shared StateInfo chain; only rolls back a
                            // scratch copy when some Sky info is missing.
                            result = detect_sky_cycle(i, ply);
                        else
                        {
                            Position rollback;
                            memcpy((void*) &rollback, (const void*) this, offsetof(Position, filter));
                            memcpy((void*) rollback.idBoard, (const void*) idBoard, sizeof(idBoard));
                            result = rollback.detect_chases(i, ply);
                        }
                    }
                    else
                        result = !checkUs ? mate_in(ply)
                               : !checkThem ? mated_in(ply)
                                            : VALUE_DRAW;

                    const bool judgedDraw = result == VALUE_DRAW;
                    apply_draw_rule(true);

                    // Legacy modes are 2-fold rules. ComputerRule preserves the stricter
                    // current Pikafish 3-fold/further-investigation behavior.
                    if (RuleConfig::repetitionRule != RR::COMPUTER)
                        return true;

                    // 3 folds and 2-fold draws (including DrawRule-transformed draws)
                    // can be judged immediately.
                    if (judgedDraw || cnt == 2)
                        return true;

                    // Preserve the current ComputerRule false-mate safeguard.
                    if (filter[st->key] <= 1)
                    {
                        if (st->rule60 < RuleConfig::rule60Limit
                            && st->previous->key == stp->previous->key)
                        {
                            StateInfo* prev = st->previous;
                            while ((prev = prev->previous) != stp)
                                if (filter[prev->key] > 1)
                                    break;
                            if (prev == stp)
                                return true;
                        }
                        break;
                    }
                }
            }

            if (i + 1 <= end)
                checkUs &= bool(stp->previous->checkersBB);
        }
    }

    // Configurable natural-move rule (rule60Limit is RULE60_UNLIMITED when the
    // Sixty Move Rule is switched off, so this is a single compare per node).
    if (st->rule60 >= RuleConfig::rule60Limit)
    {
        result = MoveList<ALL>(*this).size() ? VALUE_DRAW : mated_in(ply);
        apply_draw_rule(false);
        return true;
    }

    // YitianRule 27：总步数（双方着法总数）达到 400 步判和；33：若一方被绝杀或困毙则不判和。
    if (gamePly >= 400 && RuleConfig::repetitionRule == RuleConfig::RepetitionRule::YITIAN)
    {
        result = MoveList<ALL>(*this).size() ? VALUE_DRAW : mated_in(ply);
        apply_draw_rule(false);
        return true;
    }

    // Draw by insufficient material.
    if (count<PAWN>() == 0)
    {
        enum DrawLevel : int {
            NO_DRAW,
            DIRECT_DRAW,
            MATE_DRAW
        };

        int level = [&]() {
            if (!major_material())
                return DIRECT_DRAW;

            if (major_material() == CannonValue)
            {
                Color cannonSide = major_material(WHITE) == CannonValue ? WHITE : BLACK;
                if (count<ADVISOR>(cannonSide) == 0)
                {
                    if (count<ADVISOR>(~cannonSide) == 0)
                        return DIRECT_DRAW;

                    if (count<ADVISOR>(~cannonSide) == 1)
                        return count<BISHOP>(cannonSide) == 0 ? DIRECT_DRAW : MATE_DRAW;

                    if (count<BISHOP>(cannonSide) == 0)
                        return MATE_DRAW;
                }
            }

            if (major_material(WHITE) == CannonValue && major_material(BLACK) == CannonValue
                && count<ADVISOR>() == 0)
                return count<BISHOP>() == 0 ? DIRECT_DRAW : MATE_DRAW;

            return NO_DRAW;
        }();

        if (level != NO_DRAW)
        {
            if (level == MATE_DRAW)
            {
                MoveList<ALL> moves(*this);
                if (moves.size() == 0)
                {
                    result = mated_in(ply);
                    return true;
                }
                for (const auto& move : moves)
                {
                    StateInfo tempSt;
                    do_move(move, tempSt);
                    bool mate = MoveList<ALL>(*this).size() == 0;
                    undo_move(move);
                    if (mate)
                        return false;
                }
            }
            result = VALUE_DRAW;
            apply_draw_rule(false);
            return true;
        }
    }

    return false;
}


// Flips position with the white and black sides reversed. This
// is only useful for debugging e.g. for finding evaluation symmetry bugs.
std::optional<PositionSetError> Position::flip() {

    string            f, token;
    std::stringstream ss(fen());

    for (Rank r = RANK_9;; --r)  // Piece placement
    {
        std::getline(ss, token, r > RANK_0 ? '/' : ' ');
        f.insert(0, token + (f.empty() ? " " : "/"));

        if (r == RANK_0)
            break;
    }

    ss >> token;                        // Active color
    f += (token == "w" ? "B " : "W ");  // Will be lowercased later

    ss >> token;
    f += token + " ";

    std::transform(f.begin(), f.end(), f.begin(),
                   [](unsigned char c) { return char(islower(c) ? toupper(c) : tolower(c)); });

    ss >> token;
    f += token;

    std::getline(ss, token);  // Half and full moves
    f += token;

    return set(f, st);
}


// Performs some consistency checks for the position object
// and raise an assert if something wrong is detected.
// This is meant to be helpful when debugging.
bool Position::pos_is_ok() const {

    if ((sideToMove != WHITE && sideToMove != BLACK) || piece_on(king_square(WHITE)) != W_KING
        || piece_on(king_square(BLACK)) != B_KING)
        assert(0 && "pos_is_ok: Default");

    if (count<KING>(WHITE) != 1 || count<KING>(BLACK) != 1
        || checkers_to(sideToMove, king_square(~sideToMove)))
        assert(0 && "pos_is_ok: Kings");

    if ((pieces(WHITE, PAWN) & ~PawnBB[WHITE]) || (pieces(BLACK, PAWN) & ~PawnBB[BLACK])
        || count<PAWN>(WHITE) > 5 || count<PAWN>(BLACK) > 5)
        assert(0 && "pos_is_ok: Pawns");

    if ((pieces(WHITE) & pieces(BLACK)) || (pieces(WHITE) | pieces(BLACK)) != pieces()
        || popcount(pieces(WHITE)) > 16 || popcount(pieces(BLACK)) > 16)
        assert(0 && "pos_is_ok: Bitboards");

    for (PieceType p1 = PAWN; p1 <= KING; ++p1)
        for (PieceType p2 = PAWN; p2 <= KING; ++p2)
            if (p1 != p2 && (pieces(p1) & pieces(p2)))
                assert(0 && "pos_is_ok: Bitboards");

    for (Piece pc : Pieces)
        if (pieceCount[pc] != popcount(pieces(color_of(pc), type_of(pc)))
            || pieceCount[pc] != std::count(board.begin(), board.end(), pc))
            assert(0 && "pos_is_ok: Pieces");

    return true;
}

}  // namespace Stockfish
