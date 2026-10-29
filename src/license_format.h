/*
  幻神引擎 授权码格式 v2 (Ed25519 数字签名)  —— 引擎与 keygen 共用

  授权码 = "HS2-" + Base32(payload[25] || signature[64])，每 5 字一组用 '-' 分隔
  payload (big-endian):
     [0]      version     = 2
     [1..8]   hwid        机器码 (64-bit)
     [9..12]  issue date  签发日期 YYYYMMDD
     [13..16] expire date 到期日 YYYYMMDD (99991231 = 永久)
     [17..20] serial      授权序号 (追查外流授权用)
     [21..24] features    功能位元 (保留, 目前为 0)
  签名内容 = "HuanShenEngine/License/v2" || payload

  只有持有私钥的作者能产生有效签名; 引擎内只有公钥, 即使被反编译也无法伪造授权码。
*/

#ifndef HS_LICENSE_FORMAT_H_INCLUDED
#define HS_LICENSE_FORMAT_H_INCLUDED

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "ed25519.h"

namespace HuanShen {
namespace License {

constexpr std::uint8_t  FORMAT_VERSION  = 2;
constexpr std::size_t   PAYLOAD_BYTES   = 25;
constexpr std::size_t   BLOB_BYTES      = PAYLOAD_BYTES + Ed25519::SIGNATURE_BYTES;  // 89
constexpr std::uint32_t PERMANENT       = 99991231U;
constexpr const char*   KEY_PREFIX      = "HS2-";
constexpr const char*   SIGN_DOMAIN     = "HuanShenEngine/License/v2";
constexpr std::size_t   SIGN_DOMAIN_LEN = 25;

struct Info {
    std::uint8_t  version  = FORMAT_VERSION;
    std::uint64_t hwid     = 0;
    std::uint32_t issue    = 0;
    std::uint32_t expire   = 0;
    std::uint32_t serial   = 0;
    std::uint32_t features = 0;
};

inline void put_u32(std::uint8_t* p, std::uint32_t v) {
    for (int i = 3; i >= 0; --i, v >>= 8)
        p[i] = std::uint8_t(v);
}
inline void put_u64(std::uint8_t* p, std::uint64_t v) {
    for (int i = 7; i >= 0; --i, v >>= 8)
        p[i] = std::uint8_t(v);
}
inline std::uint32_t get_u32(const std::uint8_t* p) {
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i)
        v = (v << 8) | p[i];
    return v;
}
inline std::uint64_t get_u64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v = (v << 8) | p[i];
    return v;
}

inline std::array<std::uint8_t, PAYLOAD_BYTES> pack_payload(const Info& in) {
    std::array<std::uint8_t, PAYLOAD_BYTES> p{};
    p[0] = in.version;
    put_u64(&p[1], in.hwid);
    put_u32(&p[9], in.issue);
    put_u32(&p[13], in.expire);
    put_u32(&p[17], in.serial);
    put_u32(&p[21], in.features);
    return p;
}

inline Info unpack_payload(const std::uint8_t* p) {
    Info out;
    out.version  = p[0];
    out.hwid     = get_u64(&p[1]);
    out.issue    = get_u32(&p[9]);
    out.expire   = get_u32(&p[13]);
    out.serial   = get_u32(&p[17]);
    out.features = get_u32(&p[21]);
    return out;
}

// message actually signed = domain || payload
inline std::array<std::uint8_t, SIGN_DOMAIN_LEN + PAYLOAD_BYTES>
signing_message(const std::uint8_t* payload) {
    std::array<std::uint8_t, SIGN_DOMAIN_LEN + PAYLOAD_BYTES> m{};
    std::memcpy(m.data(), SIGN_DOMAIN, SIGN_DOMAIN_LEN);
    std::memcpy(m.data() + SIGN_DOMAIN_LEN, payload, PAYLOAD_BYTES);
    return m;
}

// ---------------------------------------------------------------- Crockford Base32
inline constexpr char B32_ALPHABET[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

inline std::string base32_encode(const std::uint8_t* data, std::size_t len) {
    std::string   out;
    std::uint32_t buffer = 0;
    int           bits   = 0;
    for (std::size_t i = 0; i < len; ++i)
    {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 5)
        {
            out.push_back(B32_ALPHABET[(buffer >> (bits - 5)) & 31]);
            bits -= 5;
        }
    }
    if (bits > 0)
        out.push_back(B32_ALPHABET[(buffer << (5 - bits)) & 31]);
    return out;
}

inline int base32_value(char c) {
    if (c >= 'a' && c <= 'z')
        c = char(c - 'a' + 'A');
    if (c == 'O')
        c = '0';
    if (c == 'I' || c == 'L')
        c = '1';
    for (int i = 0; i < 32; ++i)
        if (B32_ALPHABET[i] == c)
            return i;
    return -1;
}

// Decodes, ignoring '-', spaces and line breaks. Returns false on any invalid char.
inline bool base32_decode(const std::string& s, std::vector<std::uint8_t>& out) {
    out.clear();
    std::uint32_t buffer = 0;
    int           bits   = 0;
    for (char c : s)
    {
        if (c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        int v = base32_value(c);
        if (v < 0)
            return false;
        buffer = (buffer << 5) | std::uint32_t(v);
        bits += 5;
        if (bits >= 8)
        {
            out.push_back(std::uint8_t(buffer >> (bits - 8)));
            bits -= 8;
        }
        buffer &= 0xFFu;
    }
    return true;
}

inline std::string group5(const std::string& s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i)
    {
        if (i && i % 5 == 0)
            out.push_back('-');
        out.push_back(s[i]);
    }
    return out;
}

inline std::string encode_key(const std::uint8_t blob[BLOB_BYTES]) {
    return std::string(KEY_PREFIX) + group5(base32_encode(blob, BLOB_BYTES));
}

// Extract binary blob from a key string. Returns false if format is wrong.
inline bool decode_key(std::string key, std::array<std::uint8_t, BLOB_BYTES>& blob) {
    // trim
    while (!key.empty() && (key.back() == ' ' || key.back() == '\r' || key.back() == '\n'))
        key.pop_back();
    std::size_t start = key.find_first_not_of(" \t");
    if (start == std::string::npos)
        return false;
    key = key.substr(start);

    if (key.size() < 4)
        return false;
    std::string pre = key.substr(0, 4);
    for (auto& ch : pre)
        if (ch >= 'a' && ch <= 'z')
            ch = char(ch - 'a' + 'A');
    if (pre != KEY_PREFIX)
        return false;

    std::vector<std::uint8_t> bytes;
    if (!base32_decode(key.substr(4), bytes) || bytes.size() != BLOB_BYTES)
        return false;
    std::memcpy(blob.data(), bytes.data(), BLOB_BYTES);
    return true;
}

// Full cryptographic check. Fills `info` on success.
inline bool verify_blob(const std::array<std::uint8_t, BLOB_BYTES>& blob,
                        const std::uint8_t                          pk[32],
                        Info&                                       info) {
    const auto msg = signing_message(blob.data());
    if (!Ed25519::verify(blob.data() + PAYLOAD_BYTES, msg.data(), msg.size(), pk))
        return false;
    info = unpack_payload(blob.data());
    return info.version == FORMAT_VERSION;
}

// Machine code text "XXXX-XXXX-XXXX-XXXX" -> 64-bit hwid
inline bool parse_machine_code(const std::string& s, std::uint64_t& hwid) {
    std::uint64_t v = 0;
    int           n = 0;
    for (char c : s)
    {
        int d;
        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            d = c - 'A' + 10;
        else if (c == '-' || c == ' ')
            continue;
        else
            return false;
        v = (v << 4) | std::uint64_t(d);
        ++n;
    }
    if (n != 16)
        return false;
    hwid = v;
    return true;
}

}  // namespace License
}  // namespace HuanShen

#endif  // HS_LICENSE_FORMAT_H_INCLUDED
