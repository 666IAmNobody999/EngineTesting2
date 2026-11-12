/*
  Pikafish, a UCI chess playing engine derived from Stockfish
  Copyright (C) 2004-2026 The Stockfish developers (see AUTHORS file)

  Pikafish is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Pikafish is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef WINPERF_H_INCLUDED
#define WINPERF_H_INCLUDED

#include <cstddef>
#include <vector>

// Windows-only process tuning. Every function is a no-op on other platforms.
//
//  特調測試版 (special test build): the power plan is switched off (UsePowerPlan,
//  the code is kept), the engine's own CPU priority is only kept at "Normal" or
//  above (never raised to "High"), and other engines keep their CPU priority.
//
//  * apply_process_tuning(): CPU priority at least "Normal" (not raised to
//    "High"), I/O priority "High", memory priority "Normal", dynamic thread
//    priority boost enabled and out of EcoQoS.
//    Cheap enough to be re-applied before every search (GUIs may reset them).
//  * acquire_power_plan() / release_power_plan(): switch Windows to the
//    engine's "幻神终极效能" power plan (Bitsum Highest Performance settings:
//    core parking off, processor state 100%, P-cores preferred) while at least
//    one engine instance is running and restore the user's previous plan when the last one exits.
//    A tiny watcher process at CPU priority "Idle" (the same executable started
//    with --pikafish-power-watch <pid>) restores the plan even if the GUI kills the
//    engine instead of sending "quit".
//  * idle_other_pikafish(): sets every other process of the same user whose
//    executable name contains "pikafish", "pika", "fish", "cyclone" or
//    "bugchess" (case-insensitive) and that is not this engine's own
//    executable to I/O priority and memory priority "Very low", EcoQoS (power
//    throttling on) and no dynamic priority boost; their CPU priority is not
//    changed.
//  * boost_chess_guis(): xiangqi GUIs of the same user, i.e. processes with a
//    visible top-level window whose executable name contains "chess",
//    "chessshark", "鲨鱼象棋", "象棋", "ethinker", "pengfeichess" or "pengfei"
//    (case-insensitive) and not matched by idle_other_pikafish(), get CPU
//    priority "High" (never lowered, Realtime is left alone) and are taken out
//    of EcoQoS, so that the GUI (clocks, moves, input) stays responsive while
//    the engine searches at "High".
//  * plan_physical_core_pins(n): when n search threads fit on the physical
//    cores, one logical processor (global index group * 64 + bit) per thread,
//    each on a different physical core: performance cores first (hybrid CPUs),
//    the core of logical processor 0 last (it serves most interrupts and OS
//    work), only processors in the process affinity. Empty otherwise (more
//    threads than physical cores, or not Windows).
//  * pin_current_thread(cpu): makes that processor the calling thread's ideal
//    processor (a soft hint, no hard affinity: Windows may still move it).
//  * run_power_watcher(): returns true when this process is such a watcher;
//    main() must then return immediately.
//  * ensure_lock_pages_right(): Large Pages need the account right "Lock pages
//    in memory" (SeLockMemoryPrivilege). When it is missing: an elevated engine
//    grants it at once; an engine started by hand (console) asks Windows for
//    elevation (UAC) in the background; an engine started by a GUI never shows
//    a prompt and only prints a hint. Windows applies the right after the
//    next sign-in.
//  * run_lock_pages_helper(): returns true when this process is the elevated
//    helper (--huanshen-grant-lock-pages <SID>) started for that; main() must
//    then return immediately.

namespace Stockfish::WinPerf {

// 特調測試版: false = the "幻神终极效能" power plan is not used (code kept).
constexpr bool UsePowerPlan = false;

void apply_process_tuning();
void acquire_power_plan();
void release_power_plan();
bool run_power_watcher(int argc, char* argv[]);
void idle_other_pikafish();
void boost_chess_guis();
void ensure_lock_pages_right();
bool run_lock_pages_helper(int argc, char* argv[]);
std::vector<int> plan_physical_core_pins(std::size_t threads);
bool             pin_current_thread(int cpu);

// Platform-independent part of plan_physical_core_pins() (unit-testable).
struct PhysicalCore {
    int  efficiencyClass;  // higher = faster (P-core > E-core)
    int  firstCpu;         // first allowed logical processor, group * 64 + bit
    bool hasCpu0;          // contains logical processor 0 of group 0
};
std::vector<int> select_physical_cores(std::vector<PhysicalCore> cores, std::size_t threads);

}  // namespace Stockfish::WinPerf

#endif  // #ifndef WINPERF_H_INCLUDED
