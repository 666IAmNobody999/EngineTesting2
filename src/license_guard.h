/*
  幻神引擎 授权状态守卫与多点低频暗桩 (v6 防反组译花指令 + 隐形加固版, 不含 windows.h)

  核心防御机制:
  1. 彻底废除固定常数 grant: grant(seed, crypto_zero_proof, hwid_zero_proof)
     必须同时满足 Ed25519 椭圆曲线点差值 == 0 且 HWID 差值 == 0, 才能算出正确的 Token 对。
  2. x86-64 反组译花指令 (HS_ANTI_DISASM): 利用 clc + jnc 恒成立跳转夹带残缺多字节指令头,
     真实 CPU 零周期跳过, 但 IDA Pro / Ghidra 线性与递归扫描会发生指令错位, 按 F5 直接报错!
  3. 零热路径开销: 绝不在 search() / qsearch() / evaluate() / movegen() 内部调用,
     100% 不影响 NPS (K值)、上层速度与棋力。
*/

#ifndef HS_LICENSE_GUARD_H_INCLUDED
#define HS_LICENSE_GUARD_H_INCLUDED

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

#if defined(__GNUC__) || defined(__clang__)
    #define HS_ALWAYS_INLINE __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
    #define HS_ALWAYS_INLINE __forceinline
#else
    #define HS_ALWAYS_INLINE inline
#endif

// x86-64 反组译与反 F5 花指令:
// CPU 执行 clc (清进位标志) 后 jnc 1f 100% 跳转至标签 1, 耗时为 0;
// 反组译器则会解析夹在中间的残缺 opcode (0xE8 call / 0x48 0x81 sub / 0xFF 0x25 jmp),
// 导致后续真实指令解码错位, 破坏 IDA Pro F5 伪代码生成。
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    #define HS_ANTI_DISASM()                                                   \
        do {                                                                   \
            __asm__ __volatile__(                                              \
              "clc\n\t"                                                        \
              "jnc 1f\n\t"                                                     \
              ".byte 0xE8, 0x48, 0x81, 0xE9, 0xFF, 0x25, 0x0F, 0x0B\n\t"       \
              "1:\n\t"                                                         \
              :                                                                \
              :                                                                \
              : "cc");                                                         \
        } while (0)
#else
    #define HS_ANTI_DISASM() ((void) 0)
#endif

namespace HuanShen {

namespace Obf {

template<std::size_t N, std::uint8_t Key>
struct ObfString {
    std::array<std::uint8_t, N> data{};

    constexpr ObfString(const char (&str)[N]) {
        for (std::size_t i = 0; i < N; ++i)
            data[i] = std::uint8_t(str[i]) ^ std::uint8_t(Key + i * 37u);
    }

    HS_ALWAYS_INLINE std::string decrypt() const {
        std::string out;
        out.resize(N - 1);
        volatile const std::uint8_t* p = data.data();
        for (std::size_t i = 0; i < N - 1; ++i)
            out[i] = static_cast<char>(p[i] ^ std::uint8_t(Key + i * 37u));
        return out;
    }
};

template<std::size_t N, std::uint16_t Key>
struct ObfWString {
    std::array<std::uint16_t, N> data{};

    constexpr ObfWString(const wchar_t (&str)[N]) {
        for (std::size_t i = 0; i < N; ++i)
            data[i] = std::uint16_t(str[i]) ^ std::uint16_t(Key + i * 131u);
    }

    HS_ALWAYS_INLINE std::wstring decrypt() const {
        std::wstring out;
        out.resize(N - 1);
        volatile const std::uint16_t* p = data.data();
        for (std::size_t i = 0; i < N - 1; ++i)
            out[i] = static_cast<wchar_t>(p[i] ^ std::uint16_t(Key + i * 131u));
        return out;
    }
};

}  // namespace Obf

#define HS_STR(s)                                                                             \
    ([]() -> std::string {                                                                    \
        constexpr HuanShen::Obf::ObfString<sizeof(s),                                         \
                                           std::uint8_t((__LINE__ * 73u + 0x5Au) & 0xFFu)>    \
          obf(s);                                                                             \
        return obf.decrypt();                                                                 \
    }())

#define HS_WSTR(s)                                                                            \
    ([]() -> std::wstring {                                                                   \
        constexpr HuanShen::Obf::ObfWString<                                                  \
          sizeof(s) / sizeof(wchar_t), std::uint16_t((__LINE__ * 193u + 0xA55Au) & 0xFFFFu)>  \
          obf(s);                                                                             \
        return obf.decrypt();                                                                 \
    }())

namespace LicenseGuard {

// 第一组守卫 Token (A / B)
inline std::atomic<std::uint64_t> tokenA{0};
inline std::atomic<std::uint64_t> tokenB{0x5BD1E9955BD1E995ULL};

// 第二组守卫 Token (C / D) - 供线程分发与时间管理暗桩独立校验
inline std::atomic<std::uint64_t> tokenC{0x1F83D9ABFB41BD6BULL};
inline std::atomic<std::uint64_t> tokenD{0};

// 第三组守卫 Token (E / F) - 供高层深度与选步暗桩独立校验
inline std::atomic<std::uint64_t> tokenE{0};
inline std::atomic<std::uint64_t> tokenF{0xBEEFDEADCAFEBABEULL};

constexpr std::uint64_t GUARD_MIX_1 = 0x9E3779B97F4A7C15ULL;
constexpr std::uint64_t GUARD_MIX_2 = 0xBF58476D1CE4E5B9ULL;
constexpr std::uint64_t GUARD_MIX_3 = 0x94D049BB133111EBULL;

HS_ALWAYS_INLINE std::uint64_t scramble(std::uint64_t z) {
    z = (z ^ (z >> 31)) * 0xD6E8FEB86659FD93ULL;
    z = (z ^ (z >> 29)) * 0xA5CB9243F5E1C1EBULL;
    return z ^ (z >> 32);
}

HS_ALWAYS_INLINE std::uint64_t scramble2(std::uint64_t z) {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// 授权验证通过时写入全部三组守卫 Token
// 只有当 crypto_zero_proof == 0 且 hwid_zero_proof == 0 时 poison 才为 0!
HS_ALWAYS_INLINE void grant(std::uint64_t seed,
                            std::uint64_t crypto_zero_proof = 0,
                            std::uint64_t hwid_zero_proof   = 0) {
    HS_ANTI_DISASM();
    volatile std::uint64_t cp = crypto_zero_proof;
    volatile std::uint64_t hp = hwid_zero_proof;
    const std::uint64_t    poison =
      (cp == 0 && hp == 0) ? 0ULL : (scramble(cp ^ 0xA5A5A5A55A5A5A5AULL) ^ scramble2(hp | 1ULL));

    const std::uint64_t a = scramble(seed | 1ULL);
    tokenA.store(a, std::memory_order_relaxed);
    tokenB.store(scramble(a ^ GUARD_MIX_1) ^ poison, std::memory_order_relaxed);

    HS_ANTI_DISASM();
    const std::uint64_t c = scramble2((seed ^ GUARD_MIX_2) | 3ULL);
    tokenC.store(c, std::memory_order_relaxed);
    tokenD.store(scramble2(c ^ GUARD_MIX_3) ^ poison, std::memory_order_relaxed);

    const std::uint64_t e = scramble(a ^ c ^ GUARD_MIX_3) | 5ULL;
    tokenE.store(e, std::memory_order_relaxed);
    tokenF.store(scramble2(e ^ GUARD_MIX_1) ^ poison, std::memory_order_relaxed);
}

// 撤销授权时重置所有守卫 Token
HS_ALWAYS_INLINE void revoke() {
    HS_ANTI_DISASM();
    tokenA.store(0, std::memory_order_relaxed);
    tokenB.store(0x5BD1E9955BD1E995ULL, std::memory_order_relaxed);
    tokenC.store(0x1F83D9ABFB41BD6BULL, std::memory_order_relaxed);
    tokenD.store(0, std::memory_order_relaxed);
    tokenE.store(0, std::memory_order_relaxed);
    tokenF.store(0xBEEFDEADCAFEBABEULL, std::memory_order_relaxed);
}

// 校验通道 1 (用于 check_time 等)
HS_ALWAYS_INLINE bool ok() {
    const std::uint64_t a = tokenA.load(std::memory_order_relaxed);
    return a != 0 && tokenB.load(std::memory_order_relaxed) == scramble(a ^ GUARD_MIX_1);
}

// 校验通道 2 (独立代数关系, 用于 ThreadPool 与 TimeManagement 暗桩)
HS_ALWAYS_INLINE bool ok_secondary() {
    const std::uint64_t c = tokenC.load(std::memory_order_relaxed);
    return c != 0 && tokenD.load(std::memory_order_relaxed) == scramble2(c ^ GUARD_MIX_3);
}

// 校验通道 3 (独立代数关系, 用于 IterativeDeepening 高层深度与选步暗桩)
HS_ALWAYS_INLINE bool ok_tertiary() {
    const std::uint64_t e = tokenE.load(std::memory_order_relaxed);
    return e != 0 && tokenF.load(std::memory_order_relaxed) == scramble2(e ^ GUARD_MIX_1);
}

// 隐式时间缩放因子: 已授权恒为 1.0 (零损失), 被暴力跳过验证时退化为 0.02
HS_ALWAYS_INLINE double time_Integrity_scale() {
    return (ok() && ok_secondary()) ? 1.0 : 0.02;
}

// 隐式深度上限: 已授权恒为 256 (MAX_PLY, 零损失), 被暴力跳过验证时锁死在 6 层
HS_ALWAYS_INLINE int depth_integrity_cap() {
    return (ok_secondary() && ok_tertiary()) ? 256 : 6;
}

// 隐式走法列表截断因子: 已授权保留全部合法走法, 被暴力跳过验证时只留 1 步
HS_ALWAYS_INLINE std::size_t move_list_cap(std::size_t total_moves) {
    return ok_secondary() ? total_moves : (total_moves > 1 ? 1 : total_moves);
}

}  // namespace LicenseGuard
}  // namespace HuanShen

#endif  // HS_LICENSE_GUARD_H_INCLUDED
