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

#include <iostream>
#include <memory>
#include <utility>

#include "attacks.h"
#include "misc.h"
#include "position.h"
#include "tune.h"
#include "uci.h"
#include "winperf.h"
#include "hwid_lock.h"

using namespace Stockfish;

#ifdef UNIVERSAL_BINARY
namespace Stockfish {

int main(int argc, char* argv[]);  // silence 'no previous declaration'

__attribute__((used))  // keep main alive
#endif

int main(int argc, char* argv[]) {
    // Windows: a helper started by acquire_power_plan() only waits for its engine
    // to exit and then restores the previous power plan.
    if (WinPerf::run_power_watcher(argc, argv))
        return 0;

    // Switch Windows console to UTF-8 BEFORE printing any Chinese text to prevent garbled characters
    set_console_utf8();

    // Allow PGO build-time benchmark (`./pikafish bench`) to run during compilation
    if (argc > 1 && std::string(argv[1]) == "bench")
        HWIDLock::pgo_bench_active() = true;

    std::cout << engine_info() << std::endl;
    {
        std::string auth_msg;
        if (!HWIDLock::is_authorized("", &auth_msg, true))
            std::cout << "info string [授权状态] " << auth_msg << std::endl;
    }

    // Windows: "幻神终极效能" power plan while the engine runs.
    WinPerf::acquire_power_plan();

    Attacks::init();
    Position::init();

    auto cli = CommandLine(argc, argv);
    auto uci = std::make_unique<UCIEngine>(std::move(cli));

    Tune::init(uci->engine_options());

    uci->loop();

    WinPerf::release_power_plan();
    return 0;
}

#ifdef UNIVERSAL_BINARY
}  // namespace Stockfish

    #ifdef UNIVERSAL_NEEDS_MAIN_SHIM
int main(int argc, char* argv[]) { return Stockfish::main(argc, argv); }
    #endif
#endif
