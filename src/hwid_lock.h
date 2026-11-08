/*
  One-Machine-One-Code (一机一码) Hardware Fingerprint Authorization System
  For 幻神引擎 (v5 全内联 + 零明文字串隐形防逆向版)
*/

#ifndef HWID_LOCK_H_INCLUDED
#define HWID_LOCK_H_INCLUDED

#include <algorithm>
#include <array>
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

#include "license_format.h"
#include "license_guard.h"
#include "license_pubkey.h"

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

constexpr uint64_t HWID_SALT = 0x8F4A7C159E3779B9ULL;

constexpr bool pubkey_is_placeholder() {
    for (int i = 0; i < 32; ++i)
        if ((HuanShen::License::PUBKEY_PART_A[i] ^ HuanShen::License::PUBKEY_PART_B[i]) != 0)
            return false;
    return true;
}
static_assert(!pubkey_is_placeholder(),
              "license_pubkey.h is still the placeholder: run `hs_keygen genkey` first and "
              "copy the generated license_pubkey.h into src/");

HS_ALWAYS_INLINE void load_public_key(uint8_t pk[32]) {
    volatile const uint8_t* a = HuanShen::License::PUBKEY_PART_A;
    volatile const uint8_t* b = HuanShen::License::PUBKEY_PART_B;
    for (int i = 0; i < 32; ++i)
        pk[i] = uint8_t(a[i] ^ b[i]);
}

HS_ALWAYS_INLINE uint64_t mix64(uint64_t z) {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

inline std::string to_hex64(uint64_t val) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0') << std::setw(16) << val;
    return oss.str();
}

inline std::string to_hex32(uint32_t val) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0') << std::setw(8) << val;
    return oss.str();
}

inline std::string format_machine_code(uint64_t hwid) {
    std::string h = to_hex64(hwid);
    return h.substr(0, 4) + "-" + h.substr(4, 4) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4);
}

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

HS_ALWAYS_INLINE uint64_t hash_string(const std::string& str) {
    uint64_t hash = 14695981039346656037ULL;
    for (unsigned char c : str)
    {
        hash ^= static_cast<uint64_t>(c);
        hash *= 1099511628211ULL;
    }
    return mix64(hash ^ HWID_SALT);
}

HS_ALWAYS_INLINE uint64_t get_machine_hwid() {
    std::string raw_info = HS_STR("HUANSHEN_HWID_V2_");

#if defined(_WIN32)
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, HS_STR("SOFTWARE\\Microsoft\\Cryptography").c_str(), 0,
                      KEY_READ | KEY_WOW64_64KEY, &hKey)
        == ERROR_SUCCESS)
    {
        char  buf[256] = {0};
        DWORD bufSize  = sizeof(buf);
        if (RegQueryValueExA(hKey, HS_STR("MachineGuid").c_str(), nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(buf), &bufSize)
            == ERROR_SUCCESS)
        {
            raw_info += buf;
        }
        RegCloseKey(hKey);
    }

    DWORD serialNum = 0;
    if (GetVolumeInformationA(HS_STR("C:\\").c_str(), nullptr, 0, &serialNum, nullptr, nullptr,
                              nullptr, 0))
    {
        raw_info += "_" + std::to_string(serialNum);
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    raw_info += "_" + std::to_string(sysInfo.dwProcessorType) + "_"
              + std::to_string(sysInfo.wProcessorLevel) + "_"
              + std::to_string(sysInfo.wProcessorRevision);
#else
    std::ifstream mid(HS_STR("/etc/machine-id"));
    std::string   id;
    if (mid >> id && !id.empty())
        raw_info += id;
    else
    {
        std::ifstream cpuinfo(HS_STR("/proc/cpuinfo"));
        std::string   line;
        while (std::getline(cpuinfo, line))
        {
            if (line.find(HS_STR("Serial")) != std::string::npos
                || line.find(HS_STR("Hardware")) != std::string::npos
                || line.find(HS_STR("model name")) != std::string::npos)
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

HS_ALWAYS_INLINE uint32_t get_current_yyyymmdd() {
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

inline std::string load_saved_license() {
    const std::string     lic_filename = HS_STR("license.key");
    std::filesystem::path key_file     = get_exe_dir() / lic_filename;
    {
        std::ifstream in(key_file);
        if (in.is_open())
        {
            std::string line;
            if (std::getline(in, line) && !clean_hex_string(line).empty())
            {
                while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
                    line.pop_back();
                return line;
            }
        }
    }

    {
        std::ifstream in(lic_filename);
        if (in.is_open())
        {
            std::string line;
            if (std::getline(in, line) && !clean_hex_string(line).empty())
            {
                while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
                    line.pop_back();
                return line;
            }
        }
    }

#if defined(_WIN32)
    HKEY              hKey;
    const std::string subkey = HS_STR("Software\\HuanShenEngine\\Auth");
    if (RegOpenKeyExA(HKEY_CURRENT_USER, subkey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        char  buf[512] = {0};
        DWORD size     = sizeof(buf) - 1;
        if (RegQueryValueExA(hKey, HS_STR("LicenseKey").c_str(), nullptr, nullptr,
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

inline void save_license_key(const std::string& key_str) {
    if (key_str.empty())
        return;

    std::filesystem::path key_file = get_exe_dir() / HS_STR("license.key");
    std::ofstream         out(key_file, std::ios::trunc);
    if (out.is_open())
    {
        out << key_str << "\n";
        out.close();
    }

#if defined(_WIN32)
    HKEY              hKey;
    const std::string subkey = HS_STR("Software\\HuanShenEngine\\Auth");
    if (RegCreateKeyExA(HKEY_CURRENT_USER, subkey.c_str(), 0, nullptr, 0, KEY_WRITE, nullptr, &hKey,
                        nullptr)
        == ERROR_SUCCESS)
    {
        RegSetValueExA(hKey, HS_STR("LicenseKey").c_str(), 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(key_str.c_str()),
                       static_cast<DWORD>(key_str.size() + 1));
        RegCloseKey(hKey);
    }
#endif
}

inline void write_machine_code_file() {
    std::string           mcode    = get_machine_code_str();
    std::filesystem::path txt_file = get_exe_dir() / HS_STR("machine_code.txt");
    std::ofstream         out(txt_file, std::ios::binary | std::ios::trunc);
    if (out.is_open())
    {
        const unsigned char bom[] = {0xEF, 0xBB, 0xBF};
        out.write(reinterpret_cast<const char*>(bom), sizeof(bom));
        out << HS_STR("========================================\r\n")
            << HS_STR("  幻神引擎 (一机一码授权系统)\r\n")
            << HS_STR("========================================\r\n")
            << HS_STR("您的专属机器码 (Machine Code):\r\n\r\n    ") << mcode << "\r\n\r\n"
            << HS_STR("请将上方机器码複製发给作者以获取授权码 (License Key)。\r\n")
            << HS_STR("获取授权码后，您可以：\r\n")
            << HS_STR("1. 在象棋介面 (GUI) 引擎参数的 [License Key] 栏位填入授权码；或\r\n")
            << HS_STR("2. 将授权码存入与引擎同目录下的 license.key 档案中。\r\n");
        out.close();
    }
}

#if defined(_WIN32)
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

inline bool copy_to_windows_clipboard(const std::string& text) {
    using OpenClipboardFn    = BOOL(WINAPI*)(HWND);
    using EmptyClipboardFn   = BOOL(WINAPI*)();
    using SetClipboardDataFn = HANDLE(WINAPI*)(UINT, HANDLE);
    using CloseClipboardFn   = BOOL(WINAPI*)();

    const std::wstring u32 = HS_WSTR(L"user32.dll");
    auto pOpenClipboard    = load_win_fn<OpenClipboardFn>(u32.c_str(), HS_STR("OpenClipboard").c_str());
    auto pEmptyClipboard   = load_win_fn<EmptyClipboardFn>(u32.c_str(), HS_STR("EmptyClipboard").c_str());
    auto pSetClipboardData = load_win_fn<SetClipboardDataFn>(u32.c_str(), HS_STR("SetClipboardData").c_str());
    auto pCloseClipboard   = load_win_fn<CloseClipboardFn>(u32.c_str(), HS_STR("CloseClipboard").c_str());

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

inline void show_unauthorized_popup() {
    static bool popup_shown = false;
    if (popup_shown)
        return;
    popup_shown = true;

    std::string mcode  = get_machine_code_str();
    bool        copied = copy_to_windows_clipboard(mcode);

    using MessageBoxWFn    = int(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT);
    const std::wstring u32 = HS_WSTR(L"user32.dll");
    auto pMessageBoxW      = load_win_fn<MessageBoxWFn>(u32.c_str(), HS_STR("MessageBoxW").c_str());
    if (!pMessageBoxW)
        return;

    std::wstring wcode(mcode.begin(), mcode.end());

    std::wstring title = HS_WSTR(L"幻神引擎 - 一机一码授权提示");
    std::wstring body  = HS_WSTR(L"【幻神引擎尚未授权，或授权码无效 / 已过期】\n\n")
                       + HS_WSTR(L"您的本机专属机器码 (Machine Code)：\n👉  ") + wcode + L"\n\n";

    if (copied)
    {
        body += HS_WSTR(L"✅ 系统已自动将您的机器码複製到剪贴簿！\n"
                        L"您现在可以直接在微信 / QQ 按 Ctrl+V 贴上并发送给作者。\n\n");
    }
    else
    {
        body += HS_WSTR(L"（点击「确定」后可再次複製机器码，或打开同目录下的 machine_code.txt 查看）\n\n");
    }

    body += HS_WSTR(L"【激活方式】\n"
                    L"1. 将作者提供的 license.key 放入引擎同资料夹；或\n"
                    L"2. 在象棋介面 (GUI) 引擎参数的 [License Key] 栏位贴上授权码。");

    constexpr UINT flags = 0x00000000U | 0x00000040U | 0x00010000U | 0x00040000U;
    pMessageBoxW(nullptr, body.c_str(), title.c_str(), flags);

    copy_to_windows_clipboard(mcode);
}
#else
inline void show_unauthorized_popup() {}
#endif

HS_ALWAYS_INLINE int64_t yyyymmdd_to_days(uint32_t d) {
    int64_t y  = int64_t(d / 10000);
    int64_t m  = int64_t((d / 100) % 100);
    int64_t dd = int64_t(d % 100);
    y -= (m <= 2) ? 1 : 0;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const int64_t yoe = y - era * 400;
    const int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + dd - 1;
    const int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

HS_ALWAYS_INLINE uint32_t seen_mask(uint64_t hwid) {
    return uint32_t(mix64(hwid ^ 0xC3A5C85C97CB3127ULL));
}

HS_ALWAYS_INLINE uint32_t load_last_seen_date(uint64_t hwid) {
    uint32_t stored[2] = {0, 0};
    bool     found     = false;
#if defined(_WIN32)
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, HS_STR("Software\\HuanShenEngine\\Auth").c_str(), 0,
                      KEY_READ, &hKey)
        == ERROR_SUCCESS)
    {
        DWORD size = sizeof(stored);
        found      = RegQueryValueExA(hKey, HS_STR("Seen").c_str(), nullptr, nullptr,
                                      reinterpret_cast<LPBYTE>(stored), &size)
                    == ERROR_SUCCESS
                && size == sizeof(stored);
        RegCloseKey(hKey);
    }
#else
    std::ifstream in(get_exe_dir() / HS_STR(".hs_seen"), std::ios::binary);
    found = bool(in.read(reinterpret_cast<char*>(stored), sizeof(stored)));
#endif
    if (!found)
        return 0;
    const uint32_t date = stored[0] ^ seen_mask(hwid);
    if (stored[1] != uint32_t(mix64(uint64_t(date) ^ hwid)))
        return 0;
    return date;
}

HS_ALWAYS_INLINE void store_last_seen_date(uint64_t hwid, uint32_t date) {
    uint32_t stored[2] = {date ^ seen_mask(hwid), uint32_t(mix64(uint64_t(date) ^ hwid))};
#if defined(_WIN32)
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, HS_STR("Software\\HuanShenEngine\\Auth").c_str(), 0,
                        nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr)
        == ERROR_SUCCESS)
    {
        RegSetValueExA(hKey, HS_STR("Seen").c_str(), 0, REG_BINARY,
                       reinterpret_cast<const BYTE*>(stored), sizeof(stored));
        RegCloseKey(hKey);
    }
#else
    std::ofstream out(get_exe_dir() / HS_STR(".hs_seen"), std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(stored), sizeof(stored));
#endif
}

HS_ALWAYS_INLINE bool debugger_attached() {
#if defined(_WIN32) && !defined(HS_NO_ANTIDEBUG)
    if (IsDebuggerPresent())
        return true;
    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote)
        return true;
#endif
    return false;
}

// 强制内联 + 全字串混淆: 二进制中不再存在独立的 verify_license_key 函数入口与明文错误提示
HS_ALWAYS_INLINE bool verify_license_key(const std::string& raw_key,
                                         std::string*       status_msg = nullptr) {
    using namespace HuanShen;

    auto fail = [&](const std::string& why) {
        if (status_msg)
            *status_msg = why + HS_STR(" 本机机器码: ") + get_machine_code_str();
        return false;
    };

    std::array<uint8_t, License::BLOB_BYTES> blob{};
    if (!License::decode_key(raw_key, blob))
    {
        if (clean_hex_string(raw_key).size() == 24)
            return fail(HS_STR("旧版授权码已停用, 请向作者索取新版授权码, 机器码不变!"));
        return fail(HS_STR("授权码格式错误!"));
    }

    if (debugger_attached())
        return fail(HS_STR("检测到调试器, 授权验证已拒绝!"));

    uint8_t pk[32];
    load_public_key(pk);

    License::Info info;
    std::uint64_t crypto_proof = 0xDEAD'BEEF'CAFE'BABEULL;
    if (!License::verify_blob(blob, pk, info, &crypto_proof))
        return fail(HS_STR("授权码无效 (签名验证失败)!"));

    const uint64_t    hwid      = get_machine_hwid();
    volatile uint64_t hwid_diff = (info.hwid ^ hwid);
    if (hwid_diff != 0)
        return fail(HS_STR("此授权码不是本机专用!"));

    if (info.expire != License::PERMANENT)
    {
        const uint32_t today     = get_current_yyyymmdd();
        const int64_t  todayDays = yyyymmdd_to_days(today);

        if (todayDays + 2 < yyyymmdd_to_days(info.issue))
            return fail(HS_STR("系统日期早于授权签发日期, 请校正系统时间!"));

        const uint32_t seen = load_last_seen_date(hwid);
        if (seen && todayDays + 2 < yyyymmdd_to_days(seen))
            return fail(HS_STR("检测到系统时间被回调, 请校正系统时间!"));
        if (today > seen)
            store_last_seen_date(hwid, today);

        if (today > info.expire)
            return fail(HS_STR("授权已过期 (到期日: ") + std::to_string(info.expire) + ")!");

        if (status_msg)
            *status_msg = HS_STR("已授权 (有效至: ") + std::to_string(info.expire)
                        + HS_STR(", 序号: ") + std::to_string(info.serial) + ")";
    }
    else if (status_msg)
        *status_msg = HS_STR("已授权 (永久绑定本机, 序号: ") + std::to_string(info.serial) + ")";

    volatile uint64_t sig_part = License::get_u64(blob.data() + License::PAYLOAD_BYTES);
    LicenseGuard::grant(mix64(hwid ^ sig_part), crypto_proof, hwid_diff);
    return true;
}

#if defined(HS_PGO_PROFILE_MAKE)
inline bool& pgo_bench_active() {
    static bool active = false;
    return active;
}
#endif

struct AuthCache {
    std::string key;
    uint32_t    day = 0;
    bool        ok  = false;
    std::string msg;
};

HS_ALWAYS_INLINE bool verify_cached(const std::string& key, std::string* msg) {
    static AuthCache cache;
    const uint32_t   today = get_current_yyyymmdd();
    if (cache.ok && cache.key == key && cache.day == today && HuanShen::LicenseGuard::ok()
        && HuanShen::LicenseGuard::ok_secondary() && HuanShen::LicenseGuard::ok_tertiary())
    {
        if (msg)
            *msg = cache.msg;
        return true;
    }
    std::string m;
    const bool  ok = verify_license_key(key, &m);
    if (ok && HuanShen::LicenseGuard::ok() && HuanShen::LicenseGuard::ok_secondary()
        && HuanShen::LicenseGuard::ok_tertiary())
    {
        cache.key = key;
        cache.day = today;
        cache.ok  = true;
        cache.msg = m;
        if (msg)
            *msg = m;
        return true;
    }
    if (msg)
        *msg = m;
    return false;
}

HS_ALWAYS_INLINE bool is_authorized(const std::string& option_key  = "",
                                    std::string*       msg         = nullptr,
                                    bool               allow_popup = true) {
#if defined(HS_PGO_PROFILE_MAKE)
    if (pgo_bench_active())
    {
        HuanShen::LicenseGuard::grant(0x5047'4F42'454E'4348ULL, 0, 0);
        return true;
    }
#endif

    if (!option_key.empty() && option_key != HS_STR("<empty>"))
    {
        if (verify_cached(option_key, msg))
        {
            if (option_key != load_saved_license())
                save_license_key(option_key);
            return true;
        }
    }

    std::string saved = load_saved_license();
    if (!saved.empty() && saved != option_key)
    {
        std::string saved_msg;
        if (verify_cached(saved, &saved_msg))
        {
            if (msg)
                *msg = saved_msg;
            return true;
        }
        if (msg && msg->empty())
            *msg = saved_msg;
    }

    HuanShen::LicenseGuard::revoke();
    write_machine_code_file();
    if (msg)
    {
        std::string reason = msg->empty() ? HS_STR("未授权!") : *msg;
        *msg = reason + HS_STR(" (机器码已自动複製到剪贴簿，并已生成 machine_code.txt)");
    }

    if (allow_popup)
        show_unauthorized_popup();

    return false;
}

}  // namespace HWIDLock
}  // namespace Stockfish

#endif  // HWID_LOCK_H_INCLUDED
