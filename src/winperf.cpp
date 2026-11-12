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

#include "winperf.h"

#include <algorithm>

namespace Stockfish::WinPerf {

std::vector<int> select_physical_cores(std::vector<PhysicalCore> cores, std::size_t threads) {
    if (threads == 0 || threads > cores.size())
        return {};

    std::stable_sort(cores.begin(), cores.end(), [](const PhysicalCore& x, const PhysicalCore& y) {
        if (x.efficiencyClass != y.efficiencyClass)
            return x.efficiencyClass > y.efficiencyClass;
        if (x.hasCpu0 != y.hasCpu0)
            return y.hasCpu0;
        return x.firstCpu < y.firstCpu;
    });

    std::vector<int> pins;
    for (std::size_t i = 0; i < threads; ++i)
        pins.push_back(cores[i].firstCpu);
    return pins;
}

}  // namespace Stockfish::WinPerf

#if !defined(_WIN32)

namespace Stockfish::WinPerf {

void apply_process_tuning() {}
void acquire_power_plan() {}
void release_power_plan() {}
bool run_power_watcher(int, char*[]) { return false; }
void idle_other_pikafish() {}
void boost_chess_guis() {}
void ensure_lock_pages_right() {}
bool run_lock_pages_helper(int, char*[]) { return false; }
std::vector<int> plan_physical_core_pins(std::size_t) { return {}; }
bool             pin_current_thread(int) { return false; }

}  // namespace Stockfish::WinPerf

#else

    #if !defined(NOMINMAX)
        #define NOMINMAX
    #endif
    #if !defined(WIN32_LEAN_AND_MEAN)
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <shellapi.h>
    #include <tlhelp32.h>

    #include <atomic>
    #include <cwctype>
    #include <cstdint>
    #include <cstdlib>
    #include <cstring>
    #include <fstream>
    #include <iostream>
    #include <string>
    #include <thread>
    #include <vector>

namespace Stockfish::WinPerf {

namespace {

// All system calls below are resolved at run time, so the engine still starts on
// Windows versions (or SDKs) that lack one of them, and no extra import library
// is needed for any toolchain. A failing call is silently ignored.
template<typename F>
F load(const wchar_t* dll, const char* name) {
    HMODULE mod = GetModuleHandleW(dll);
    if (!mod)
        mod = LoadLibraryW(dll);
    F       fn   = nullptr;
    FARPROC proc = mod ? GetProcAddress(mod, name) : nullptr;
    if (proc)
        std::memcpy(&fn, &proc, sizeof(fn));
    return fn;
}

// ---------------------------------------------------------------------------
// Process tuning: I/O priority, memory priority, dynamic priority boost
// ---------------------------------------------------------------------------

using NtSetInformationProcessFn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG);
using SetProcessInformationFn   = BOOL(WINAPI*)(HANDLE, int, LPVOID, DWORD);

constexpr ULONG ProcessIoPriority     = 33;  // PROCESSINFOCLASS::ProcessIoPriority
constexpr ULONG IoPriorityVeryLow     = 0;
constexpr ULONG IoPriorityNormal      = 2;
constexpr ULONG IoPriorityHigh        = 3;
constexpr int   ProcessMemoryPriority = 0;  // PROCESS_INFORMATION_CLASS::ProcessMemoryPriority
constexpr ULONG MemoryPriorityVeryLow = 1;  // MEMORY_PRIORITY_VERY_LOW
constexpr ULONG MemoryPriorityNormal  = 5;  // MEMORY_PRIORITY_NORMAL

// PROCESS_INFORMATION_CLASS::ProcessPowerThrottling and its
// PROCESS_POWER_THROTTLING_STATE (Windows 10 1709 and later; EcoQoS on Windows 11).
constexpr int   ProcessPowerThrottling          = 4;
constexpr ULONG PowerThrottlingVersion          = 1;
constexpr ULONG PowerThrottlingExecutionSpeed   = 0x1;
constexpr ULONG PowerThrottlingIgnoreTimerRes   = 0x4;
struct PowerThrottlingState {
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
};

bool enable_privilege(const wchar_t* name) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid)
           && AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr)
           && GetLastError() == ERROR_SUCCESS;  // ERROR_NOT_ALL_ASSIGNED: not held
    CloseHandle(token);
    return ok;
}

// ---------------------------------------------------------------------------
// Power plan
// ---------------------------------------------------------------------------

using PowerGetActiveSchemeFn  = DWORD(WINAPI*)(HKEY, GUID**);
using PowerSetActiveSchemeFn  = DWORD(WINAPI*)(HKEY, const GUID*);
using PowerEnumerateFn        = DWORD(WINAPI*)(HKEY, const GUID*, const GUID*, int, ULONG, UCHAR*, DWORD*);
using PowerReadFriendlyNameFn = DWORD(WINAPI*)(HKEY, const GUID*, const GUID*, const GUID*, UCHAR*, DWORD*);
using PowerDuplicateSchemeFn  = DWORD(WINAPI*)(HKEY, const GUID*, GUID**);
using PowerWriteFriendlyNameFn = DWORD(WINAPI*)(HKEY, const GUID*, const GUID*, const GUID*, UCHAR*, DWORD);
using PowerWriteValueIndexFn   = DWORD(WINAPI*)(HKEY, const GUID*, const GUID*, const GUID*, DWORD);

constexpr int  AccessScheme = 16;  // POWER_DATA_ACCESSOR::ACCESS_SCHEME
constexpr GUID UltimateGuid = {0xe9a42b02, 0xd5df, 0x448d, {0xaa, 0x00, 0x03, 0xf1, 0x47, 0x49, 0xeb, 0x61}};
constexpr GUID HighPerfGuid = {0x8c5e7fda, 0xe8bf, 0x4a96, {0x9a, 0x85, 0xa6, 0xe2, 0x3a, 0x8c, 0x63, 0x5c}};

// Name of the engine's own power plan.
constexpr wchar_t PlanName[] = L"\u5E7B\u795E\u7EC8\u6781\u6548\u80FD";  // 幻神终极效能
// Bitsum Highest Performance (installed by Process Lasso / ParkControl) is
// copied when present; it is never modified or renamed, so Process Lasso keeps
// finding it.
constexpr wchar_t BitsumName[] = L"Bitsum Highest Performance";

// Processor settings of Bitsum Highest Performance, applied to the plan on
// both AC and DC (https://bitsum.com/bhp/: core parking off, CPU never below
// its base frequency; Process Lasso changelog: prefer P-cores for short and
// long running threads). Settings missing on a CPU (e.g. no hybrid cores) are
// skipped by Windows.
constexpr GUID SubProcessor = {0x54533251, 0x82be, 0x4824, {0x96, 0xc1, 0x47, 0xb6, 0x0b, 0x74, 0x0d, 0x00}};
struct PlanSetting {
    GUID  setting;
    DWORD value;
};
constexpr PlanSetting PlanSettings[] = {
  {{0x0cc5b647, 0xc1df, 0x4637, {0x89, 0x1a, 0xde, 0xc3, 0x5c, 0x31, 0x85, 0x84}}, 100},  // CPMINCORES
  {{0x0cc5b647, 0xc1df, 0x4637, {0x89, 0x1a, 0xde, 0xc3, 0x5c, 0x31, 0x85, 0x85}}, 100},  // CPMINCORES1
  {{0xea062031, 0x0e34, 0x4ff1, {0x9b, 0x6d, 0xeb, 0x10, 0x59, 0x33, 0x40, 0x28}}, 100},  // CPMAXCORES
  {{0xea062031, 0x0e34, 0x4ff1, {0x9b, 0x6d, 0xeb, 0x10, 0x59, 0x33, 0x40, 0x29}}, 100},  // CPMAXCORES1
  {{0x893dee8e, 0x2bef, 0x41e0, {0x89, 0xc6, 0xb5, 0x5d, 0x09, 0x29, 0x96, 0x4c}}, 100},  // PROCTHROTTLEMIN
  {{0x893dee8e, 0x2bef, 0x41e0, {0x89, 0xc6, 0xb5, 0x5d, 0x09, 0x29, 0x96, 0x4d}}, 100},  // PROCTHROTTLEMIN1
  {{0xbc5038f7, 0x23e0, 0x4960, {0x96, 0xda, 0x33, 0xab, 0xaf, 0x59, 0x35, 0xec}}, 100},  // PROCTHROTTLEMAX
  {{0xbc5038f7, 0x23e0, 0x4960, {0x96, 0xda, 0x33, 0xab, 0xaf, 0x59, 0x35, 0xed}}, 100},  // PROCTHROTTLEMAX1
  {{0x93b8b6dc, 0x0698, 0x4d1c, {0x9e, 0xe4, 0x06, 0x44, 0xe9, 0x00, 0xc8, 0x5d}}, 2},    // SCHEDPOLICY: prefer performant
  {{0xbae08b81, 0x2d5e, 0x4688, {0xad, 0x6a, 0x13, 0x24, 0x33, 0x56, 0x65, 0x4b}}, 2},    // SHORTSCHEDPOLICY
};
constexpr char WatchSwitch[] = "--pikafish-power-watch";

struct PowerApi {
    PowerGetActiveSchemeFn  getActive = load<PowerGetActiveSchemeFn>(L"powrprof.dll", "PowerGetActiveScheme");
    PowerSetActiveSchemeFn  setActive = load<PowerSetActiveSchemeFn>(L"powrprof.dll", "PowerSetActiveScheme");
    PowerEnumerateFn        enumerate = load<PowerEnumerateFn>(L"powrprof.dll", "PowerEnumerate");
    PowerReadFriendlyNameFn readName  = load<PowerReadFriendlyNameFn>(L"powrprof.dll", "PowerReadFriendlyName");
    PowerDuplicateSchemeFn  duplicate = load<PowerDuplicateSchemeFn>(L"powrprof.dll", "PowerDuplicateScheme");
    PowerWriteFriendlyNameFn writeName = load<PowerWriteFriendlyNameFn>(L"powrprof.dll", "PowerWriteFriendlyName");
    PowerWriteValueIndexFn   writeAC   = load<PowerWriteValueIndexFn>(L"powrprof.dll", "PowerWriteACValueIndex");
    PowerWriteValueIndexFn   writeDC   = load<PowerWriteValueIndexFn>(L"powrprof.dll", "PowerWriteDCValueIndex");

    bool ok() const { return getActive && setActive && enumerate; }
};

PowerApi& power() {
    static PowerApi api;
    return api;
}

bool same(const GUID& a, const GUID& b) { return std::memcmp(&a, &b, sizeof(GUID)) == 0; }

bool active_scheme(GUID& out) {
    GUID* p = nullptr;
    if (power().getActive(nullptr, &p) != ERROR_SUCCESS || !p)
        return false;
    out = *p;
    LocalFree(p);
    return true;
}

std::wstring friendly_name(const GUID& g) {
    if (!power().readName)
        return {};
    DWORD size = 0;
    DWORD rc   = power().readName(nullptr, &g, nullptr, nullptr, nullptr, &size);
    if ((rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA) || size < sizeof(wchar_t))
        return {};
    std::vector<UCHAR> buf(size + sizeof(wchar_t), 0);
    if (power().readName(nullptr, &g, nullptr, nullptr, buf.data(), &size) != ERROR_SUCCESS)
        return {};
    return std::wstring(reinterpret_cast<const wchar_t*>(buf.data()));
}

std::wstring data_dir() {
    wchar_t buf[MAX_PATH];
    DWORD   n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
    {
        n = GetTempPathW(MAX_PATH, buf);
        if (n == 0 || n >= MAX_PATH)
            return {};
    }
    std::wstring dir(buf);
    if (!dir.empty() && dir.back() != L'\\')
        dir += L'\\';
    dir += L"Pikafish";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L'\\';
}

// GUID of the plan created by the engine (kept so that it is created only once).
std::wstring created_scheme_file() { return data_dir() + L"power_plan.guid"; }
std::wstring state_file() { return data_dir() + L"powerplan.state"; }

template<typename Fn>
bool for_each_scheme(Fn fn) {
    for (ULONG i = 0;; ++i)
    {
        GUID  s{};
        DWORD size = sizeof(s);
        if (power().enumerate(nullptr, nullptr, nullptr, AccessScheme, i, reinterpret_cast<UCHAR*>(&s), &size)
            != ERROR_SUCCESS)
            return false;
        if (fn(s))
            return true;
    }
}

bool scheme_exists(const GUID& g) {
    return for_each_scheme([&](const GUID& s) { return same(s, g); });
}

bool scheme_named(const wchar_t* name, GUID& out) {
    return for_each_scheme([&](const GUID& s) {
        if (friendly_name(s) != name)
            return false;
        out = s;
        return true;
    });
}

bool duplicate_scheme(const GUID& source, GUID& out) {
    GUID* dup = nullptr;
    if (!power().duplicate || power().duplicate(nullptr, &source, &dup) != ERROR_SUCCESS || !dup)
        return false;
    out = *dup;
    LocalFree(dup);
    return true;
}

// Applies the Bitsum Highest Performance processor settings (idempotent).
void configure_plan(const GUID& plan) {
    for (const auto& ps : PlanSettings)
    {
        if (power().writeAC)
            power().writeAC(nullptr, &plan, &SubProcessor, &ps.setting, ps.value);
        if (power().writeDC)
            power().writeDC(nullptr, &plan, &SubProcessor, &ps.setting, ps.value);
    }
}

// Finds the engine's "幻神终极效能" plan, creating it once when missing: a copy
// of Bitsum Highest Performance if installed, else of the (possibly hidden)
// Ultimate Performance template, else of High Performance. The Bitsum settings
// are (re-)applied on every start.
bool find_power_plan(GUID& out) {
    std::wstring createdFile = created_scheme_file();
    bool         found       = false;
    {
        std::ifstream f(createdFile.c_str(), std::ios::binary);
        GUID          g{};
        if (f.read(reinterpret_cast<char*>(&g), sizeof(g)) && scheme_exists(g))
        {
            out   = g;
            found = true;
        }
    }
    if (!found)
        found = scheme_named(PlanName, out);

    if (!found)
    {
        GUID bitsum{};
        if (!(scheme_named(BitsumName, bitsum) && duplicate_scheme(bitsum, out))
            && !duplicate_scheme(UltimateGuid, out) && !duplicate_scheme(HighPerfGuid, out))
            return false;

        if (power().writeName)
        {
            std::wstring name(PlanName);
            power().writeName(nullptr, &out, nullptr, nullptr, reinterpret_cast<UCHAR*>(name.data()),
                              DWORD((name.size() + 1) * sizeof(wchar_t)));
        }
        std::ofstream f(createdFile.c_str(), std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(&out), sizeof(out));
    }

    configure_plan(out);
    return true;
}

// Shared state of all running engine instances (several engines may run at the
// same time, e.g. in an engine match): the plan to restore and the processes
// still using the engine's power plan. Guarded by a named mutex.
struct Instance {
    DWORD    pid;
    FILETIME created;
};

struct State {
    GUID                  original{};
    GUID                  ultimate{};  // the engine's plan
    std::uint32_t         switched = 0;  // the engine changed the plan and must restore it
    std::vector<Instance> instances;
};

constexpr std::uint32_t StateMagic = 0x57504B50;  // "PKPW"

bool read_state(State& s) {
    std::ifstream f(state_file().c_str(), std::ios::binary);
    std::uint32_t magic = 0, n = 0;
    if (!f.read(reinterpret_cast<char*>(&magic), sizeof(magic)) || magic != StateMagic)
        return false;
    f.read(reinterpret_cast<char*>(&s.original), sizeof(s.original));
    f.read(reinterpret_cast<char*>(&s.ultimate), sizeof(s.ultimate));
    f.read(reinterpret_cast<char*>(&s.switched), sizeof(s.switched));
    f.read(reinterpret_cast<char*>(&n), sizeof(n));
    if (!f || n > 4096)
        return false;
    s.instances.resize(n);
    f.read(reinterpret_cast<char*>(s.instances.data()), std::streamsize(n * sizeof(Instance)));
    return bool(f);
}

void write_state(const State& s) {
    std::ofstream f(state_file().c_str(), std::ios::binary | std::ios::trunc);
    std::uint32_t n = std::uint32_t(s.instances.size());
    f.write(reinterpret_cast<const char*>(&StateMagic), sizeof(StateMagic));
    f.write(reinterpret_cast<const char*>(&s.original), sizeof(s.original));
    f.write(reinterpret_cast<const char*>(&s.ultimate), sizeof(s.ultimate));
    f.write(reinterpret_cast<const char*>(&s.switched), sizeof(s.switched));
    f.write(reinterpret_cast<const char*>(&n), sizeof(n));
    f.write(reinterpret_cast<const char*>(s.instances.data()), std::streamsize(n * sizeof(Instance)));
}

bool same_time(const FILETIME& a, const FILETIME& b) {
    return a.dwLowDateTime == b.dwLowDateTime && a.dwHighDateTime == b.dwHighDateTime;
}

bool alive(const Instance& in) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, in.pid);
    if (!h)
        return GetLastError() == ERROR_ACCESS_DENIED;  // exists, but not ours to inspect
    FILETIME c, e, k, u;
    bool     ok = WaitForSingleObject(h, 0) == WAIT_TIMEOUT && GetProcessTimes(h, &c, &e, &k, &u)
          && same_time(c, in.created);
    CloseHandle(h);
    return ok;
}

void prune(State& s) {
    std::vector<Instance> live;
    for (const auto& in : s.instances)
        if (alive(in))
            live.push_back(in);
    s.instances.swap(live);
}

class StateLock {
   public:
    StateLock() {
        mutex = CreateMutexW(nullptr, FALSE, L"Local\\Pikafish.PowerPlan");
        if (mutex)
        {
            DWORD rc = WaitForSingleObject(mutex, 10000);
            locked   = rc == WAIT_OBJECT_0 || rc == WAIT_ABANDONED;
        }
    }
    ~StateLock() {
        if (locked)
            ReleaseMutex(mutex);
        if (mutex)
            CloseHandle(mutex);
    }
    explicit operator bool() const { return locked; }

   private:
    HANDLE mutex  = nullptr;
    bool   locked = false;
};

// Removes `pid` from the shared state; the last instance restores the plan.
void release_instance(DWORD pid) {
    if (!power().ok())
        return;
    StateLock lock;
    if (!lock)
        return;
    State s;
    if (!read_state(s))
        return;

    std::vector<Instance> rest;
    for (const auto& in : s.instances)
        if (in.pid != pid)
            rest.push_back(in);
    s.instances.swap(rest);
    prune(s);

    if (!s.instances.empty())
    {
        write_state(s);
        return;
    }

    // Restore only if the plan is still the one the engine selected, so a plan
    // the user picked by hand while the engine was running is kept.
    GUID cur{};
    if (s.switched && active_scheme(cur) && same(cur, s.ultimate))
        power().setActive(nullptr, &s.original);
    DeleteFileW(state_file().c_str());
}

void spawn_watcher(DWORD pid) {
    std::vector<wchar_t> exe(32768);
    DWORD                n = GetModuleFileNameW(nullptr, exe.data(), DWORD(exe.size()));
    if (n == 0 || n >= exe.size())
        return;

    std::wstring cmd = L"\"" + std::wstring(exe.data(), n) + L"\" ";
    for (const char* c = WatchSwitch; *c; ++c)
        cmd += wchar_t(*c);
    cmd += L" " + std::to_wstring(pid);

    // No inherited handles: the watcher must not keep the GUI's pipes open.
    // Break away from the GUI's job object when allowed, so that killing the
    // engine's job does not take the watcher with it.
    // CPU priority "Idle": the watcher only sleeps until the engine exits.
    DWORD flags = CREATE_NO_WINDOW | IDLE_PRIORITY_CLASS;
    for (DWORD extra : {DWORD(CREATE_BREAKAWAY_FROM_JOB), DWORD(0)})
    {
        STARTUPINFOW        si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);
        std::vector<wchar_t> line(cmd.begin(), cmd.end());
        line.push_back(L'\0');
        if (CreateProcessW(nullptr, line.data(), nullptr, nullptr, FALSE, flags | extra, nullptr, nullptr,
                           &si, &pi))
        {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return;
        }
    }
}

std::atomic<bool> powerAcquired{false};

BOOL WINAPI console_handler(DWORD type) {
    if (type == CTRL_CLOSE_EVENT || type == CTRL_LOGOFF_EVENT || type == CTRL_SHUTDOWN_EVENT)
        release_power_plan();
    return FALSE;  // let the default handling continue
}

}  // namespace

void apply_process_tuning() {
    HANDLE proc = GetCurrentProcess();

    // 1. CPU priority: at least Normal (特調測試版: not raised to High). Only a
    //    priority below Normal (Idle / Below normal) is lifted back to Normal.
    const DWORD pc = GetPriorityClass(proc);
    if (pc == IDLE_PRIORITY_CLASS || pc == BELOW_NORMAL_PRIORITY_CLASS)
        SetPriorityClass(proc, NORMAL_PRIORITY_CLASS);

    // 2. Dynamic thread priority boost on (FALSE = boost not disabled).
    BOOL boostDisabled = FALSE;
    if (GetProcessPriorityBoost(proc, &boostDisabled) && boostDisabled)
        SetProcessPriorityBoost(proc, FALSE);

    // 3. I/O priority: High. Windows only grants it with
    //    SeIncreaseBasePriorityPrivilege (an elevated administrator); otherwise
    //    fall back to Normal so that a GUI-lowered priority is still undone.
    static auto  ntSet   = load<NtSetInformationProcessFn>(L"ntdll.dll", "NtSetInformationProcess");
    static ULONG ioLevel = IoPriorityHigh;
    static bool  ioTried = false;
    if (ntSet && ioLevel)
    {
        ULONG io = ioLevel;
        LONG  st = ntSet(proc, ProcessIoPriority, &io, sizeof(io));
        if (st < 0 && !ioTried)
        {
            if (enable_privilege(L"SeIncreaseBasePriorityPrivilege"))
                st = ntSet(proc, ProcessIoPriority, &io, sizeof(io));
            if (st < 0)
            {
                io      = ioLevel = IoPriorityNormal;
                st      = ntSet(proc, ProcessIoPriority, &io, sizeof(io));
                ioLevel = st < 0 ? 0 : IoPriorityNormal;
            }
        }
        ioTried = true;
    }

    // 4. Memory priority: Normal (Windows 8 and later).
    static auto setInfo = load<SetProcessInformationFn>(L"kernel32.dll", "SetProcessInformation");
    if (setInfo)
    {
        ULONG mem = MemoryPriorityNormal;  // MEMORY_PRIORITY_INFORMATION
        setInfo(proc, ProcessMemoryPriority, &mem, sizeof(mem));

        // 5. Out of EcoQoS / power throttling: full clock speed and the
        //    performance cores even when the GUI window is in the background,
        //    and timer resolution requests honoured.
        PowerThrottlingState pt{PowerThrottlingVersion,
                                PowerThrottlingExecutionSpeed | PowerThrottlingIgnoreTimerRes, 0};
        setInfo(proc, ProcessPowerThrottling, &pt, sizeof(pt));
    }
}

void acquire_power_plan() {
    if (powerAcquired.load() || !power().ok())
        return;

    Instance self{GetCurrentProcessId(), {}};
    FILETIME e, k, u;
    if (!GetProcessTimes(GetCurrentProcess(), &self.created, &e, &k, &u))
        return;

    {
        StateLock lock;
        if (!lock)
            return;

        State s;
        bool  hadState = read_state(s);
        prune(s);

        if (s.instances.empty())
        {
            GUID cur{}, ult{};
            if (!active_scheme(cur) || !find_power_plan(ult))
                return;

            // Every engine was killed before it could restore (and its watcher
            // was killed as well): the plan saved then is still the one to restore.
            bool stale = hadState && s.switched && same(s.ultimate, ult) && same(cur, ult);
            if (!stale)
            {
                s          = State{};
                s.original = cur;
                s.ultimate = ult;
                s.switched = !same(cur, ult) && power().setActive(nullptr, &ult) == ERROR_SUCCESS;
            }
            if (same(cur, ult))
                power().setActive(nullptr, &ult);  // re-activate so the refreshed settings apply
        }

        s.instances.push_back(self);
        write_state(s);
        powerAcquired = true;
    }

    std::atexit(release_power_plan);
    SetConsoleCtrlHandler(console_handler, TRUE);
    spawn_watcher(self.pid);
}

void release_power_plan() {
    if (powerAcquired.exchange(false))
        release_instance(GetCurrentProcessId());
}

bool run_power_watcher(int argc, char* argv[]) {
    if (argc < 3 || std::strcmp(argv[1], WatchSwitch) != 0)
        return false;

    // Keep the watcher at "Idle" even if it was started some other way.
    SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);

    DWORD pid = DWORD(std::strtoul(argv[2], nullptr, 10));
    if (HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid))
    {
        WaitForSingleObject(h, INFINITE);
        CloseHandle(h);
    }
    release_instance(pid);
    return true;
}

namespace {

std::wstring lower(std::wstring s) {
    for (auto& c : s)
        c = wchar_t(std::towlower(c));
    return s;
}

std::wstring image_path(HANDLE proc) {
    std::vector<wchar_t> buf(32768);
    DWORD                size = DWORD(buf.size());
    if (!QueryFullProcessImageNameW(proc, 0, buf.data(), &size))
        return {};
    return lower(std::wstring(buf.data(), size));
}

// TOKEN_USER of a process (owner SID), empty on failure.
std::vector<BYTE> token_user(HANDLE proc) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(proc, TOKEN_QUERY, &token))
        return {};
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buf(size);
    if (!size || !GetTokenInformation(token, TokenUser, buf.data(), size, &size))
        buf.clear();
    CloseHandle(token);
    return buf;
}

bool same_user(const std::vector<BYTE>& a, const std::vector<BYTE>& b) {
    return !a.empty() && !b.empty()
        && EqualSid(reinterpret_cast<const TOKEN_USER*>(a.data())->User.Sid,
                    reinterpret_cast<const TOKEN_USER*>(b.data())->User.Sid);
}

}  // namespace

// Executable names (lower case, substring match) of the engines put to "Idle".
constexpr const wchar_t* IdleNames[] = {L"pikafish", L"pika", L"fish", L"cyclone", L"bugchess"};

static bool idle_name(const std::wstring& exe) {
    const std::wstring name = lower(exe);
    for (const wchar_t* n : IdleNames)
        if (name.find(n) != std::wstring::npos)
            return true;
    return false;
}

void idle_other_pikafish() {
    const DWORD             selfPid  = GetCurrentProcessId();
    const std::wstring      selfPath = image_path(GetCurrentProcess());
    const std::vector<BYTE> selfUser = token_user(GetCurrentProcess());
    if (selfPath.empty() || selfUser.empty())
        return;

    static auto ntSet   = load<NtSetInformationProcessFn>(L"ntdll.dll", "NtSetInformationProcess");
    static auto setInfo = load<SetProcessInformationFn>(L"kernel32.dll", "SetProcessInformation");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32W e{};
    e.dwSize = sizeof(e);
    for (BOOL ok = Process32FirstW(snap, &e); ok; ok = Process32NextW(snap, &e))
    {
        if (e.th32ProcessID == selfPid || !idle_name(e.szExeFile))
            continue;

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION, FALSE,
                               e.th32ProcessID);
        if (!h)
            continue;  // other users / protected processes are never touched

        // Same user only; copies of this very executable (other instances of
        // this engine and its own watchers) are left alone.
        if (same_user(token_user(h), selfUser) && image_path(h) != selfPath)
        {
            // I/O priority and memory priority "Very low", EcoQoS (power
            // throttling on) and no dynamic priority boost. 特調測試版: the CPU
            // priority is left as it is (neither raised nor lowered).
            BOOL boostDisabled = FALSE;
            if (GetProcessPriorityBoost(h, &boostDisabled) && !boostDisabled)
                SetProcessPriorityBoost(h, TRUE);
            if (ntSet)
            {
                ULONG io = IoPriorityVeryLow;
                ntSet(h, ProcessIoPriority, &io, sizeof(io));
            }
            if (setInfo)
            {
                ULONG mem = MemoryPriorityVeryLow;  // MEMORY_PRIORITY_INFORMATION
                setInfo(h, ProcessMemoryPriority, &mem, sizeof(mem));
                PowerThrottlingState pt{PowerThrottlingVersion, PowerThrottlingExecutionSpeed,
                                        PowerThrottlingExecutionSpeed};
                setInfo(h, ProcessPowerThrottling, &pt, sizeof(pt));
            }
        }
        CloseHandle(h);
    }
    CloseHandle(snap);
}

// Executable names (lower case, substring match) of the xiangqi GUIs raised to
// "High": chess, chessshark, 鲨鱼象棋, 象棋, ethinker, pengfeichess, pengfei.
// explorer.exe (exact name) is raised too, keeping the Windows shell smooth.
constexpr const wchar_t* GuiNames[] = {L"chess",
                                       L"chessshark",
                                       L"\u9ca8\u9c7c\u8c61\u68cb",  // 鲨鱼象棋
                                       L"\u8c61\u68cb",                // 象棋
                                       L"ethinker",
                                       L"pengfeichess",
                                       L"pengfei"};

static bool gui_name(const std::wstring& exe) {
    const std::wstring name = lower(exe);
    if (name == L"explorer.exe")  // Windows shell: taskbar, desktop, file windows
        return true;
    for (const wchar_t* n : GuiNames)
        if (name.find(n) != std::wstring::npos)
            return true;
    return false;
}

using EnumWindowsFn              = BOOL(WINAPI*)(WNDENUMPROC, LPARAM);
using IsWindowVisibleFn          = BOOL(WINAPI*)(HWND);
using GetWindowFn                = HWND(WINAPI*)(HWND, UINT);
using GetWindowThreadProcessIdFn = DWORD(WINAPI*)(HWND, LPDWORD);

struct User32 {
    EnumWindowsFn     enumWindows = load<EnumWindowsFn>(L"user32.dll", "EnumWindows");
    IsWindowVisibleFn visible     = load<IsWindowVisibleFn>(L"user32.dll", "IsWindowVisible");
    GetWindowFn       getWindow   = load<GetWindowFn>(L"user32.dll", "GetWindow");
    GetWindowThreadProcessIdFn windowPid =
      load<GetWindowThreadProcessIdFn>(L"user32.dll", "GetWindowThreadProcessId");

    bool ok() const { return enumWindows && visible && getWindow && windowPid; }
};

static User32& user32() {
    static User32 u;
    return u;
}

// Processes owning a visible top-level window (GUIs; engines have none).
static BOOL CALLBACK collect_window_pid(HWND hwnd, LPARAM out) {
    if (user32().visible(hwnd) && !user32().getWindow(hwnd, GW_OWNER))
    {
        DWORD pid = 0;
        user32().windowPid(hwnd, &pid);
        if (pid)
            reinterpret_cast<std::vector<DWORD>*>(out)->push_back(pid);
    }
    return TRUE;
}

void boost_chess_guis() {
    if (!user32().ok())
        return;

    const DWORD             selfPid  = GetCurrentProcessId();
    const std::wstring      selfPath = image_path(GetCurrentProcess());
    const std::vector<BYTE> selfUser = token_user(GetCurrentProcess());
    if (selfPath.empty() || selfUser.empty())
        return;

    std::vector<DWORD> windowed;
    user32().enumWindows(collect_window_pid, reinterpret_cast<LPARAM>(&windowed));
    if (windowed.empty())
        return;
    std::sort(windowed.begin(), windowed.end());

    static auto setInfo = load<SetProcessInformationFn>(L"kernel32.dll", "SetProcessInformation");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32W e{};
    e.dwSize = sizeof(e);
    for (BOOL ok = Process32FirstW(snap, &e); ok; ok = Process32NextW(snap, &e))
    {
        if (e.th32ProcessID == selfPid || idle_name(e.szExeFile) || !gui_name(e.szExeFile)
            || !std::binary_search(windowed.begin(), windowed.end(), e.th32ProcessID))
            continue;

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION, FALSE,
                               e.th32ProcessID);
        if (!h)
            continue;  // other users / elevated GUIs are never touched

        if (same_user(token_user(h), selfUser) && image_path(h) != selfPath)
        {
            const DWORD pc = GetPriorityClass(h);
            if (pc && pc != HIGH_PRIORITY_CLASS && pc != REALTIME_PRIORITY_CLASS)
                SetPriorityClass(h, HIGH_PRIORITY_CLASS);
            if (setInfo)
            {
                PowerThrottlingState pt{PowerThrottlingVersion, PowerThrottlingExecutionSpeed, 0};
                setInfo(h, ProcessPowerThrottling, &pt, sizeof(pt));
            }
        }
        CloseHandle(h);
    }
    CloseHandle(snap);
}

std::vector<int> plan_physical_core_pins(std::size_t threads) {
    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || len == 0)
        return {};
    std::vector<char> buf(len);
    auto* base = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buf.data());
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, base, &len))
        return {};

    // A process living in a single processor group (the usual case) can only
    // run on its affinity mask; on multi-group systems every group is usable.
    bool      filter = false;
    USHORT    procGroup = 0;
    DWORD_PTR procMask = 0, sysMask = 0;
    {
        USHORT groups[64];
        USHORT count = 64;
        if (GetProcessGroupAffinity(GetCurrentProcess(), &count, groups) && count == 1
            && GetProcessAffinityMask(GetCurrentProcess(), &procMask, &sysMask))
        {
            filter    = true;
            procGroup = groups[0];
        }
    }

    std::vector<PhysicalCore> cores;
    for (DWORD off = 0; off < len;)
    {
        auto* info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buf.data() + off);
        if (info->Size == 0)
            break;
        off += info->Size;
        if (info->Relationship != RelationProcessorCore || info->Processor.GroupCount == 0)
            continue;

        const GROUP_AFFINITY& ga   = info->Processor.GroupMask[0];
        KAFFINITY             mask = ga.Mask;
        if (filter)
            mask = ga.Group == procGroup ? mask & KAFFINITY(procMask) : 0;
        if (!mask)
            continue;

        int bit = 0;
        while (!((mask >> bit) & 1))
            ++bit;
        cores.push_back({int(info->Processor.EfficiencyClass), int(ga.Group) * 64 + bit,
                         ga.Group == 0 && (ga.Mask & 1)});
    }

    return select_physical_cores(std::move(cores), threads);
}

bool pin_current_thread(int cpu) {
    if (cpu < 0)
        return false;
    // Soft hint only ("ideal processor"): Windows runs the thread there when it
    // can, but moves it to another processor when that one is busy (other
    // games, the GUI, the SMT sibling in use), so it is never stuck waiting.
    PROCESSOR_NUMBER pn{};
    pn.Group  = WORD(cpu / 64);
    pn.Number = BYTE(cpu % 64);
    return SetThreadIdealProcessorEx(GetCurrentThread(), &pn, nullptr) != 0;
}


// ---------------------------------------------------------------------------
// Large Pages: account right "Lock pages in memory" (SeLockMemoryPrivilege)
// ---------------------------------------------------------------------------

namespace {

constexpr const char*    LockPagesSwitch = "--huanshen-grant-lock-pages";
constexpr const wchar_t* LockPagesRight  = L"SeLockMemoryPrivilege";
constexpr ACCESS_MASK    PolicyLookupNames  = 0x00000800;  // POLICY_LOOKUP_NAMES
constexpr ACCESS_MASK    PolicyCreateAccount = 0x00000010;  // POLICY_CREATE_ACCOUNT
constexpr LONG           StatusObjectNameNotFound = LONG(0xC0000034);

// LSA_UNICODE_STRING / LSA_OBJECT_ATTRIBUTES (ntsecapi.h)
struct LsaString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};
struct LsaObjectAttributes {
    ULONG      Length;
    HANDLE     RootDirectory;
    LsaString* ObjectName;
    ULONG      Attributes;
    PVOID      SecurityDescriptor;
    PVOID      SecurityQualityOfService;
};

using LsaOpenPolicyFn = LONG(WINAPI*)(LsaString*, LsaObjectAttributes*, ACCESS_MASK, HANDLE*);
using LsaAddAccountRightsFn       = LONG(WINAPI*)(HANDLE, PSID, LsaString*, ULONG);
using LsaEnumerateAccountRightsFn = LONG(WINAPI*)(HANDLE, PSID, LsaString**, ULONG*);
using LsaFreeMemoryFn             = LONG(WINAPI*)(PVOID);
using LsaCloseFn                  = LONG(WINAPI*)(HANDLE);
using ConvertSidToStringSidWFn    = BOOL(WINAPI*)(PSID, LPWSTR*);
using ConvertStringSidToSidWFn    = BOOL(WINAPI*)(LPCWSTR, PSID*);
using ShellExecuteExWFn           = BOOL(WINAPI*)(SHELLEXECUTEINFOW*);
using CoInitializeExFn            = HRESULT(WINAPI*)(LPVOID, DWORD);

struct Lsa {
    LsaOpenPolicyFn open = load<LsaOpenPolicyFn>(L"advapi32.dll", "LsaOpenPolicy");
    LsaAddAccountRightsFn add = load<LsaAddAccountRightsFn>(L"advapi32.dll", "LsaAddAccountRights");
    LsaEnumerateAccountRightsFn enumerate =
      load<LsaEnumerateAccountRightsFn>(L"advapi32.dll", "LsaEnumerateAccountRights");
    LsaFreeMemoryFn free  = load<LsaFreeMemoryFn>(L"advapi32.dll", "LsaFreeMemory");
    LsaCloseFn      close = load<LsaCloseFn>(L"advapi32.dll", "LsaClose");
    ConvertSidToStringSidWFn sidToString =
      load<ConvertSidToStringSidWFn>(L"advapi32.dll", "ConvertSidToStringSidW");
    ConvertStringSidToSidWFn stringToSid =
      load<ConvertStringSidToSidWFn>(L"advapi32.dll", "ConvertStringSidToSidW");

    bool ok() const { return open && add && enumerate && free && close && sidToString && stringToSid; }
};

Lsa& lsa() {
    static Lsa l;
    return l;
}

LsaString lock_right_name() {
    LsaString s;
    s.Buffer        = const_cast<PWSTR>(LockPagesRight);
    s.Length        = USHORT(std::wcslen(LockPagesRight) * sizeof(wchar_t));
    s.MaximumLength = USHORT(s.Length + sizeof(wchar_t));
    return s;
}

HANDLE open_policy(ACCESS_MASK access) {
    LsaObjectAttributes attr{};
    attr.Length   = sizeof(attr);
    HANDLE policy = nullptr;
    return lsa().open(nullptr, &attr, access, &policy) >= 0 ? policy : nullptr;
}

// 1: the account has the right, 0: it has not, -1: unknown.
int account_has_lock_right(PSID sid) {
    HANDLE policy = open_policy(PolicyLookupNames);
    if (!policy)
        return -1;

    LsaString* rights = nullptr;
    ULONG      count  = 0;
    const LONG st     = lsa().enumerate(policy, sid, &rights, &count);
    int        result = st == StatusObjectNameNotFound ? 0 : -1;
    if (st >= 0)
    {
        const LsaString want = lock_right_name();
        result               = 0;
        for (ULONG i = 0; i < count; ++i)
            if (rights[i].Length == want.Length
                && !std::wcsncmp(rights[i].Buffer, want.Buffer, want.Length / sizeof(wchar_t)))
                result = 1;
        lsa().free(rights);
    }
    lsa().close(policy);
    return result;
}

bool grant_lock_right(PSID sid) {
    HANDLE policy = open_policy(PolicyLookupNames | PolicyCreateAccount);
    if (!policy)
        return false;
    LsaString  right = lock_right_name();
    const bool ok    = lsa().add(policy, sid, &right, 1) >= 0;
    lsa().close(policy);
    return ok;
}

bool token_has_lock_privilege() {
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, LockPagesRight, &luid))
        return false;

    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    DWORD size = 0;
    GetTokenInformation(token, TokenPrivileges, nullptr, 0, &size);
    std::vector<BYTE> buf(size);
    bool              found = false;
    if (size && GetTokenInformation(token, TokenPrivileges, buf.data(), size, &size))
    {
        const auto* tp = reinterpret_cast<const TOKEN_PRIVILEGES*>(buf.data());
        for (DWORD i = 0; i < tp->PrivilegeCount; ++i)
            if (tp->Privileges[i].Luid.LowPart == luid.LowPart
                && tp->Privileges[i].Luid.HighPart == luid.HighPart)
                found = true;
    }
    CloseHandle(token);
    return found;
}

bool process_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION e{};
    DWORD           size = 0;
    const bool      ok =
      GetTokenInformation(token, TokenElevation, &e, sizeof(e), &size) && e.TokenIsElevated;
    CloseHandle(token);
    return ok;
}

void lock_pages_info(const char* msg) {
    std::cout << "info string Large Pages: " << msg << std::endl;
}

// Starts this executable elevated (UAC) as the helper that grants the right to
// the given account. Runs on its own thread: the prompt never blocks the engine.
void request_elevated_grant(const std::wstring& sidString) {
    std::vector<wchar_t> exe(32768);
    DWORD                n = GetModuleFileNameW(nullptr, exe.data(), DWORD(exe.size()));
    if (n == 0 || n >= exe.size())
        return;

    std::wstring path(exe.data(), n), params;
    for (const char* c = LockPagesSwitch; *c; ++c)
        params += wchar_t(*c);
    params += L" " + sidString;

    std::thread([path, params]() {
        static auto shellExecute = load<ShellExecuteExWFn>(L"shell32.dll", "ShellExecuteExW");
        static auto coInit       = load<CoInitializeExFn>(L"ole32.dll", "CoInitializeEx");
        if (!shellExecute)
            return;
        if (coInit)
            coInit(nullptr, 0x2 | 0x4);  // COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE

        SHELLEXECUTEINFOW sei{};
        sei.cbSize       = sizeof(sei);
        sei.fMask        = SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        sei.lpVerb       = L"runas";
        sei.lpFile       = path.c_str();
        sei.lpParameters = params.c_str();
        sei.nShow        = SW_HIDE;
        shellExecute(&sei);
    }).detach();
}

}  // namespace

void ensure_lock_pages_right() {
    if (!GetLargePageMinimum() || token_has_lock_privilege() || !lsa().ok())
        return;  // no Large Pages on this system, or already usable

    const std::vector<BYTE> user = token_user(GetCurrentProcess());
    if (user.empty())
        return;
    PSID sid = reinterpret_cast<const TOKEN_USER*>(user.data())->User.Sid;

    if (account_has_lock_right(sid) == 1)
    {
        lock_pages_info("\"Lock pages in memory\" is granted, sign out and in again to use it");
        return;
    }

    if (process_elevated())
    {
        lock_pages_info(grant_lock_right(sid)
                          ? "\"Lock pages in memory\" granted, sign out and in again to use it"
                          : "could not grant \"Lock pages in memory\"");
        return;
    }

    // Not elevated. A GUI talks to the engine through pipes: never show a UAC
    // prompt there (it would take over the screen during a game). Only when the
    // engine was started by hand (console input) is Windows asked for it.
    DWORD mode = 0;
    if (!GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode))
    {
        lock_pages_info("not available, start the engine once by double-clicking it "
                        "to grant \"Lock pages in memory\"");
        return;
    }

    LPWSTR sidString = nullptr;
    if (!lsa().sidToString(sid, &sidString) || !sidString)
        return;
    request_elevated_grant(sidString);
    LocalFree(sidString);
    lock_pages_info("asking Windows (UAC) for \"Lock pages in memory\"; "
                    "after accepting, sign out and in again");
}

bool run_lock_pages_helper(int argc, char* argv[]) {
    if (argc < 3 || std::strcmp(argv[1], LockPagesSwitch) != 0)
        return false;

    if (lsa().ok())
    {
        std::wstring sidString;
        for (const char* c = argv[2]; *c; ++c)
            sidString += wchar_t(*c);
        PSID sid = nullptr;
        if (lsa().stringToSid(sidString.c_str(), &sid) && sid)
        {
            grant_lock_right(sid);
            LocalFree(sid);
        }
    }
    return true;
}

}  // namespace Stockfish::WinPerf

#endif  // _WIN32
