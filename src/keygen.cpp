/*
  幻神引擎 - 作者專用算號器 (One-Machine-One-Code Keygen)
  編譯指令: g++ -std=c++17 -O2 keygen.cpp -o keygen.exe
*/

#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

constexpr uint64_t SECRET_KEY_1  = 0x8F4A7C159E3779B9ULL;
constexpr uint64_t SECRET_KEY_2  = 0xD1B54A32D192ED03ULL;
constexpr uint64_t SECRET_KEY_3  = 0x94D049BB133111EBULL;
constexpr uint64_t MIX_CONST_1   = 0xBF58476D1CE4E5B9ULL;
constexpr uint32_t DATE_OBF_MASK = 0x5A93C6E1U;

inline uint64_t mix64(uint64_t z) {
    z = (z ^ (z >> 30)) * MIX_CONST_1;
    z = (z ^ (z >> 27)) * SECRET_KEY_3;
    return z ^ (z >> 31);
}

inline uint64_t compute_signature(uint64_t hwid, uint32_t expire_date) {
    uint64_t a = mix64(hwid ^ SECRET_KEY_1);
    uint64_t b = mix64(((static_cast<uint64_t>(expire_date) << 32) | expire_date) ^ SECRET_KEY_2);
    return mix64(a ^ b ^ SECRET_KEY_3);
}

inline std::string clean_hex_string(const std::string& input) {
    std::string out;
    for (unsigned char c : input)
    {
        if (std::isxdigit(c))
            out.push_back(static_cast<char>(std::toupper(c)));
    }
    return out;
}

inline std::string to_hex(uint64_t val, int width) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0') << std::setw(width) << val;
    return oss.str();
}

inline std::string generate_license_key(uint64_t hwid, uint32_t exp_date) {
    uint32_t date_key = static_cast<uint32_t>((hwid ^ (hwid >> 32)) & 0xFFFFFFFFULL) ^ DATE_OBF_MASK;
    uint32_t obf_date = exp_date ^ date_key;
    uint64_t sig      = compute_signature(hwid, exp_date);

    std::string raw = to_hex(obf_date, 8) + to_hex(sig, 16);
    return raw.substr(0, 4) + "-" + raw.substr(4, 4) + "-" + raw.substr(8, 4) + "-"
         + raw.substr(12, 4) + "-" + raw.substr(16, 4) + "-" + raw.substr(20, 4);
}

int main(int argc, char* argv[]) {
    std::string machine_code;
    uint32_t    exp_date = 99991231U;

    if (argc >= 2)
    {
        machine_code = argv[1];
        if (argc >= 3)
            exp_date = static_cast<uint32_t>(std::stoul(argv[2]));
    }
    else
    {
        std::cout << "================================================\n"
                  << "      幻神引擎 - 一機一碼作者專用算號器\n"
                  << "================================================\n"
                  << "請輸入買家的機器碼 (例如 A1B2-C3D4-E5F6-0123): ";
        std::getline(std::cin, machine_code);

        std::cout << "請輸入到期日 YYYYMMDD (直接按 Enter 預設為 99991231 永久授權): ";
        std::string date_str;
        std::getline(std::cin, date_str);
        if (!date_str.empty())
            exp_date = static_cast<uint32_t>(std::stoul(date_str));
    }

    std::string cleaned = clean_hex_string(machine_code);
    if (cleaned.size() != 16)
    {
        std::cerr << "[錯誤] 機器碼格式不正確！必須為 16 位十六進制字元。\n";
        return 1;
    }

    uint64_t hwid = 0;
    {
        std::istringstream iss(cleaned);
        iss >> std::hex >> hwid;
    }

    std::string license_key = generate_license_key(hwid, exp_date);

    std::cout << "\n------------------------------------------------\n"
              << "買家機器碼 (Machine Code) : " << cleaned.substr(0, 4) << "-" << cleaned.substr(4, 4)
              << "-" << cleaned.substr(8, 4) << "-" << cleaned.substr(12, 4) << "\n"
              << "授權有效期 (Expiration)   : "
              << (exp_date == 99991231U ? "永久授權 (99991231)" : std::to_string(exp_date)) << "\n"
              << "專屬授權碼 (License Key)  : " << license_key << "\n"
              << "------------------------------------------------\n";

    std::ofstream out("license.key", std::ios::trunc);
    if (out.is_open())
    {
        out << license_key << "\n";
        out.close();
        std::cout << "[成功] 已同步在當前目錄生成 license.key 檔案！\n";
    }

    return 0;
}
