/*
  One-Machine-One-Code (一机一码) Hardware Fingerprint Authorization System
  For 幻神引擎 (Commercial Edition with Native Popup & Auto-Clipboard)
*/

#ifndef HWID_LOCK_H_INCLUDED
#define HWID_LOCK_H_INCLUDED

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#if defined(_WIN32)
    #if !defined(NOMINMAX)
        #define NOMINMAX
    #endif
    #if !defined(WIN32_LEAN_AND_MEAN)
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#else
    #include <limits.h>
    #include <sys/stat.h>
    #include <unistd.h>
#endif

namespace Stockfish {
namespace HWIDLock {

// ============================================================================
// AUTHOR SECRET KEYS (Keep identical to Keygen!)
// ============================================================================
constexpr uint64_t SECRET_KEY_1  = 0x8F4A7C159E3779B9ULL;
constexpr uint64_t SECRET_KEY_2  = 0xD1B54A32D192ED03ULL;
constexpr uint64_t SECRET_KEY_3  = 0x94D049BB133111EBULL;
constexpr uint32_t DATE_OBF_MASK = 0x5A93C6E1U;

// SplitMix64 mixing function (cryptographic-style non-linear bit mixer)
inline uint64_t mix64(uint64_t z) {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// Compute 64-bit signature for (hwid, expire_yyyymmdd)
inline uint64_t compute_signature(uint64_t hwid, uint32_t expire_date) {
    uint64_t a = mix64(hwid ^ SECRET_KEY_1);
    uint64_t b = mix64(((static_cast<uint64_t>(expire_date) << 32) | expire_date) ^ SECRET_KEY_2);
    return mix64(a ^ b ^ SECRET_KEY_3);
}

// Format 64-bit integer as 16-char uppercase hex
inline std::string to_hex64(uint64_t val) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0') << std::setw(16) << val;
    return oss.str();
}

// Format 32-bit integer as 8-char uppercase hex
inline std::string to_hex32(uint32_t val) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0') << std::setw(8) << val;
    return oss.str();
}

// Format 64-bit HWID into XXXX-XXXX-XXXX-XXXX
inline std::string format_machine_code(uint64_t hwid) {
    std::string h = to_hex64(hwid);
    return h.substr(0, 4) + "-" + h.substr(4, 4) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4);
}

// Strip all non-hex characters and uppercase
inline std::string clean_hex_string(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (unsigned char c : input)
    {
        if (std::isxdigit(c))
            out.push_back(static_cast<char>(std::toupper(c)));
    }
    return out;
}

// FNV-1a 64-bit hash
inline uint64_t hash_string(const std::string& str) {
    uint64_t hash = 14695981039346656037ULL;
    for (unsigned char c : str)
    {
        hash ^= static_cast<uint64_t>(c);
        hash *= 1099511628211ULL;
    }
    return mix64(hash ^ SECRET_KEY_1);
}

// Obtain unique hardware fingerprint for current machine
inline uint64_t get_machine_hwid() {
    std::string raw_info = "HUANSHEN_HWID_V2_";

#if defined(_WIN32)
    // 1. Windows Cryptography MachineGuid
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0,
                      KEY_READ | KEY_WOW64_64KEY, &hKey)
        == ERROR_SUCCESS)
    {
        char  buf[256] = {0};
        DWORD bufSize  = sizeof(buf);
        if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(buf), &bufSize)
            == ERROR_SUCCESS)
        {
            raw_info += buf;
        }
        RegCloseKey(hKey);
    }

    // 2. System Volume Serial Number
    DWORD serialNum = 0;
    if (GetVolumeInformationA("C:\\", nullptr, 0, &serialNum, nullptr, nullptr, nullptr, 0))
    {
        raw_info += "_" + std::to_string(serialNum);
    }

    // 3. CPU Architecture & Revision features
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    raw_info += "_" + std::to_string(sysInfo.dwProcessorType) + "_"
              + std::to_string(sysInfo.wProcessorLevel) + "_"
              + std::to_string(sysInfo.wProcessorRevision);
#else
    // Linux / Android / macOS machine identifier
    std::ifstream mid("/etc/machine-id");
    std::string   id;
    if (mid >> id && !id.empty())
        raw_info += id;
    else
    {
        std::ifstream cpuinfo("/proc/cpuinfo");
        std::string   line;
        while (std::getline(cpuinfo, line))
        {
            if (line.find("Serial") != std::string::npos
                || line.find("Hardware") != std::string::npos
                || line.find("model name") != std::string::npos)
            {
                raw_info += line;
            }
        }
        char hostname[256] = {0};
        if (gethostname(hostname, sizeof(hostname)) == 0)
            raw_info += hostname;
    }
#endif

    return hash_string(raw_info);
}

inline std::string get_machine_code_str() {
    return format_machine_code(get_machine_hwid());
}

// Get current local date as YYYYMMDD integer
inline uint32_t get_current_yyyymmdd() {
    std::time_t t = std::time(nullptr);
    std::tm     tm_buf{};
#if defined(_WIN32)
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    uint32_t year  = static_cast<uint32_t>(tm_buf.tm_year + 1900);
    uint32_t month = static_cast<uint32_t>(tm_buf.tm_mon + 1);
    uint32_t day   = static_cast<uint32_t>(tm_buf.tm_mday);
    return year * 10000U + month * 100U + day;
}

// Get executable directory
inline std::filesystem::path get_exe_dir() {
#if defined(_WIN32)
    wchar_t path[MAX_PATH] = {0};
    DWORD   len            = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (len > 0)
        return std::filesystem::path(path).parent_path();
#else
    char    path[PATH_MAX] = {0};
    ssize_t count          = readlink("/proc/self/exe", path, PATH_MAX);
    if (count > 0)
        return std::filesystem::path(std::string(path, static_cast<size_t>(count))).parent_path();
#endif
    return std::filesystem::current_path();
}

// Read saved license key from license.key or Registry
inline std::string load_saved_license() {
    // 1. Check license.key in executable directory
    std::filesystem::path key_file = get_exe_dir() / "license.key";
    {
        std::ifstream in(key_file);
        if (in.is_open())
        {
            std::string line;
            if (std::getline(in, line) && !clean_hex_string(line).empty())
                return line;
        }
    }

    // 2. Check license.key in current working directory
    {
        std::ifstream in("license.key");
        if (in.is_open())
        {
            std::string line;
            if (std::getline(in, line) && !clean_hex_string(line).empty())
                return line;
        }
    }

#if defined(_WIN32)
    // 3. Check Windows Registry
    HKEY        hKey;
    const char* subkey = "Software\\HuanShenEngine\\Auth";
    if (RegOpenKeyExA(HKEY_CURRENT_USER, subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        char  buf[256] = {0};
        DWORD size     = sizeof(buf);
        if (RegQueryValueExA(hKey, "LicenseKey", nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(buf), &size)
            == ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            return std::string(buf);
        }
        RegCloseKey(hKey);
    }
#endif

    return "";
}

// Persist valid license key to both license.key and Registry
inline void save_license_key(const std::string& key_str) {
    if (key_str.empty())
        return;

    std::filesystem::path key_file = get_exe_dir() / "license.key";
    std::ofstream         out(key_file, std::ios::trunc);
    if (out.is_open())
    {
        out << key_str << "\n";
        out.close();
    }

#if defined(_WIN32)
    HKEY        hKey;
    const char* subkey = "Software\\HuanShenEngine\\Auth";
    if (RegCreateKeyExA(HKEY_CURRENT_USER, subkey, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey,
                        nullptr)
        == ERROR_SUCCESS)
    {
        RegSetValueExA(hKey, "LicenseKey", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(key_str.c_str()),
                       static_cast<DWORD>(key_str.size() + 1));
        RegCloseKey(hKey);
    }
#endif
}

// Write machine code helper txt file (with UTF-8 BOM so Windows Notepad never garbles)
inline void write_machine_code_file() {
    std::string           mcode    = get_machine_code_str();
    std::filesystem::path txt_file = get_exe_dir() / "machine_code.txt";
    std::ofstream         out(txt_file, std::ios::binary | std::ios::trunc);
    if (out.is_open())
    {
        // Write UTF-8 BOM
        const unsigned char bom[] = {0xEF, 0xBB, 0xBF};
        out.write(reinterpret_cast<const char*>(bom), sizeof(bom));
        out << "========================================\r\n"
            << "  幻神引擎 (一机一码授权系统)\r\n"
            << "========================================\r\n"
            << "您的专属机器码 (Machine Code):\r\n\r\n"
            << "    " << mcode << "\r\n\r\n"
            << "请将上方机器码複製发给作者以获取授权码 (License Key)。\r\n"
            << "获取授权码后，您可以：\r\n"
            << "1. 在象棋介面 (GUI) 引擎参数的 [License Key] 栏位填入授权码；或\r\n"
            << "2. 将授权码存入与引擎同目录下的 license.key 档案中。\r\n";
        out.close();
    }
}

#if defined(_WIN32)
// Dynamically resolve user32.dll functions so no extra linker flags (-luser32) are required
template<typename F>
inline F load_win_fn(const wchar_t* dll, const char* name) {
    HMODULE mod = GetModuleHandleW(dll);
    if (!mod)
        mod = LoadLibraryW(dll);
    F       fn   = nullptr;
    FARPROC proc = mod ? GetProcAddress(mod, name) : nullptr;
    if (proc)
        std::memcpy(&fn, &proc, sizeof(fn));
    return fn;
}

// Copy ASCII string to Windows Clipboard automatically
inline bool copy_to_windows_clipboard(const std::string& text) {
    using OpenClipboardFn    = BOOL(WINAPI*)(HWND);
    using EmptyClipboardFn   = BOOL(WINAPI*)();
    using SetClipboardDataFn = HANDLE(WINAPI*)(UINT, HANDLE);
    using CloseClipboardFn   = BOOL(WINAPI*)();

    auto pOpenClipboard    = load_win_fn<OpenClipboardFn>(L"user32.dll", "OpenClipboard");
    auto pEmptyClipboard   = load_win_fn<EmptyClipboardFn>(L"user32.dll", "EmptyClipboard");
    auto pSetClipboardData = load_win_fn<SetClipboardDataFn>(L"user32.dll", "SetClipboardData");
    auto pCloseClipboard   = load_win_fn<CloseClipboardFn>(L"user32.dll", "CloseClipboard");

    if (!pOpenClipboard || !pEmptyClipboard || !pSetClipboardData || !pCloseClipboard)
        return false;

    if (!pOpenClipboard(nullptr))
        return false;

    pEmptyClipboard();
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!hMem)
    {
        pCloseClipboard();
        return false;
    }

    void* ptr = GlobalLock(hMem);
    if (ptr)
    {
        std::memcpy(ptr, text.c_str(), text.size() + 1);
        GlobalUnlock(hMem);
    }

    constexpr UINT kCF_TEXT = 1;
    if (!pSetClipboardData(kCF_TEXT, hMem))
    {
        GlobalFree(hMem);
        pCloseClipboard();
        return false;
    }

    pCloseClipboard();
    return true;
}

// Show a native UTF-16 Windows popup dialog (100% immune to console codepage garbling)
// Returns true if user clicked Yes/OK
inline void show_unauthorized_popup() {
    static bool popup_shown = false;
    if (popup_shown)
        return;
    popup_shown = true;

    std::string mcode  = get_machine_code_str();
    bool        copied = copy_to_windows_clipboard(mcode);

    using MessageBoxWFn = int(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT);
    auto pMessageBoxW   = load_win_fn<MessageBoxWFn>(L"user32.dll", "MessageBoxW");
    if (!pMessageBoxW)
        return;

    std::wstring wcode(mcode.begin(), mcode.end());

    std::wstring title = L"幻神引擎 - 一机一码授权提示";
    std::wstring body  = L"【幻神引擎尚未授权，或授权码无效 / 已过期】\n\n"
                       + std::wstring(L"您的本机专属机器码 (Machine Code)：\n")
                       + L"👉  " + wcode + L"\n\n";

    if (copied)
    {
        body += L"✅ 系统已自动将您的机器码複製到剪贴簿！\n"
                L"您现在可以直接在微信 / QQ 按 Ctrl+V 贴上并发送给作者。\n\n";
    }
    else
    {
        body += L"（点击「确定」后可再次複製机器码，或打开同目录下的 machine_code.txt 查看）\n\n";
    }

    body += L"【激活方式】\n"
            L"1. 将作者提供的 license.key 放入引擎同资料夹；或\n"
            L"2. 在象棋介面 (GUI) 引擎参数的 [License Key] 栏位贴上授权码。";

    // MB_OK (0x00) | MB_ICONINFORMATION (0x40) | MB_SETFOREGROUND (0x10000) | MB_TOPMOST (0x40000)
    constexpr UINT flags = 0x00000000U | 0x00000040U | 0x00010000U | 0x00040000U;
    pMessageBoxW(nullptr, body.c_str(), title.c_str(), flags);

    // Ensure clipboard still holds the machine code after clicking OK
    copy_to_windows_clipboard(mcode);
}
#else
inline void show_unauthorized_popup() {}
#endif

// Verify a license key string against current machine HWID and current date
inline bool verify_license_key(const std::string& raw_key, std::string* status_msg = nullptr) {
    std::string cleaned = clean_hex_string(raw_key);
    if (cleaned.size() != 24)
    {
        if (status_msg)
            *status_msg = "未授权 (本机机器码: " + get_machine_code_str() + ")";
        return false;
    }

    uint32_t obf_date = 0;
    uint64_t sig      = 0;

    {
        std::istringstream iss1(cleaned.substr(0, 8));
        iss1 >> std::hex >> obf_date;
        std::istringstream iss2(cleaned.substr(8, 16));
        iss2 >> std::hex >> sig;
    }

    uint64_t hwid     = get_machine_hwid();
    uint32_t date_key = static_cast<uint32_t>((hwid ^ (hwid >> 32)) & 0xFFFFFFFFULL) ^ DATE_OBF_MASK;
    uint32_t exp_date = obf_date ^ date_key;

    uint64_t expected_sig = compute_signature(hwid, exp_date);
    if (sig != expected_sig)
    {
        if (status_msg)
            *status_msg = "授权码无效或非本机专用! 本机机器码: " + get_machine_code_str();
        return false;
    }

    // Check expiration (99991231 = Permanent)
    if (exp_date != 99991231U)
    {
        uint32_t today = get_current_yyyymmdd();
        if (today > exp_date)
        {
            if (status_msg)
                *status_msg = "授权已过期 (到期日: " + std::to_string(exp_date)
                            + ")! 本机机器码: " + get_machine_code_str();
            return false;
        }
        if (status_msg)
            *status_msg = "已授权 (有效至: " + std::to_string(exp_date) + ")";
    }
    else
    {
        if (status_msg)
            *status_msg = "已授权 (永久绑定本机)";
    }

    return true;
}

// Internal flag for PGO build-time benchmark only
inline bool& pgo_bench_active() {
    static bool active = false;
    return active;
}

// Global authorization state check (checks current option value + saved file/registry)
inline bool is_authorized(const std::string& option_key  = "",
                          std::string*       msg         = nullptr,
                          bool               allow_popup = true) {
    if (pgo_bench_active())
        return true;

    if (!option_key.empty() && option_key != "<empty>")
    {
        if (verify_license_key(option_key, msg))
        {
            save_license_key(option_key);
            return true;
        }
    }

    std::string saved = load_saved_license();
    if (!saved.empty())
    {
        if (verify_license_key(saved, msg))
            return true;
    }

    write_machine_code_file();
    if (msg)
        *msg = "未授权! 本机机器码: " + get_machine_code_str()
             + " (机器码已自动複製到剪贴簿，并已生成 machine_code.txt)";

    if (allow_popup)
        show_unauthorized_popup();

    return false;
}

}  // namespace HWIDLock
}  // namespace Stockfish

#endif  // HWID_LOCK_H_INCLUDED
