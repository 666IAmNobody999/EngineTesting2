/*
  One-Machine-One-Code (一機一碼) Hardware Fingerprint Authorization System
  For 幻神引擎 (EngineProject-Testing)
*/

#ifndef HWID_LOCK_H_INCLUDED
#define HWID_LOCK_H_INCLUDED

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
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

// Write machine code helper txt file when unauthorized
inline void write_machine_code_file() {
    std::string           mcode    = get_machine_code_str();
    std::filesystem::path txt_file = get_exe_dir() / "machine_code.txt";
    std::ofstream         out(txt_file, std::ios::trunc);
    if (out.is_open())
    {
        out << "========================================\n"
            << "  幻神引擎 (一機一碼授權系統)\n"
            << "========================================\n"
            << "您的專屬機器碼 (Machine Code):\n\n"
            << "    " << mcode << "\n\n"
            << "請將上方機器碼複製發給作者以獲取授權碼 (License Key)。\n"
            << "獲取授權碼後，您可以：\n"
            << "1. 在象棋介面 (GUI) 引擎參數的 [License Key] 欄位填入授權碼；或\n"
            << "2. 將授權碼存入與引擎同目錄下的 license.key 檔案中。\n";
        out.close();
    }
}

// Verify a license key string against current machine HWID and current date
inline bool verify_license_key(const std::string& raw_key, std::string* status_msg = nullptr) {
    std::string cleaned = clean_hex_string(raw_key);
    if (cleaned.size() != 24)
    {
        if (status_msg)
            *status_msg = "未授權 (本機機器碼: " + get_machine_code_str() + ")";
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
            *status_msg = "授權碼無效或非本機專用! 本機機器碼: " + get_machine_code_str();
        return false;
    }

    // Check expiration (99991231 = Permanent)
    if (exp_date != 99991231U)
    {
        uint32_t today = get_current_yyyymmdd();
        if (today > exp_date)
        {
            if (status_msg)
                *status_msg = "授權已過期 (到期日: " + std::to_string(exp_date)
                            + ")! 本機機器碼: " + get_machine_code_str();
            return false;
        }
        if (status_msg)
            *status_msg = "已授權 (有效至: " + std::to_string(exp_date) + ")";
    }
    else
    {
        if (status_msg)
            *status_msg = "已授權 (永久綁定本機)";
    }

    return true;
}

// Internal flag for PGO build-time benchmark only
inline bool& pgo_bench_active() {
    static bool active = false;
    return active;
}

// Global authorization state check (checks current option value + saved file/registry)
inline bool is_authorized(const std::string& option_key = "", std::string* msg = nullptr) {
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
        *msg = "未授權! 本機機器碼: " + get_machine_code_str()
             + " (已生成 machine_code.txt，請聯繫作者獲取授權碼)";
    return false;
}

}  // namespace HWIDLock
}  // namespace Stockfish

#endif  // HWID_LOCK_H_INCLUDED
