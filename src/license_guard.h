/*
  幻神引擎 授权状态守卫与多点低频暗桩 (防 NOP 补丁强化版, 不含 windows.h)

  核心防御机制:
  - 彻底废除固定常数 grant: grant(seed, crypto_zero_proof, hwid_zero_proof)
    必须同时满足 Ed25519 椭圆曲线点差值 == 0 且 HWID 差值 == 0, 才能算出正确的 Token 对。
    即使破解者用 90 90 (NOP) 跳过所有 if 条件判断, 只要没有正版授权码, 传入的差值就是非 0 乱数,
    写入的 Token 必定被毒化, 后续 4 处低频暗桩将 100% 触发!
  - 零热路径开销: 绝不在 search() / qsearch() / evaluate() / movegen() 内部调用,
    100% 不影响 NPS (K值)、上层速度与棋力。
*/

#ifndef HS_LICENSE_GUARD_H_INCLUDED
#define HS_LICENSE_GUARD_H_INCLUDED

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace HuanShen {
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

inline std::uint64_t scramble(std::uint64_t z) {
    z = (z ^ (z >> 31)) * 0xD6E8FEB86659FD93ULL;
    z = (z ^ (z >> 29)) * 0xA5CB9243F5E1C1EBULL;
    return z ^ (z >> 32);
}

inline std::uint64_t scramble2(std::uint64_t z) {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// 授权验证通过时写入全部三组守卫 Token
// 只有当 crypto_zero_proof == 0 且 hwid_zero_proof == 0 时 poison 才为 0!
inline void grant(std::uint64_t seed,
                  std::uint64_t crypto_zero_proof = 0,
                  std::uint64_t hwid_zero_proof   = 0) {
    volatile std::uint64_t cp = crypto_zero_proof;
    volatile std::uint64_t hp = hwid_zero_proof;
    const std::uint64_t    poison =
      (cp == 0 && hp == 0) ? 0ULL : (scramble(cp ^ 0xA5A5A5A55A5A5A5AULL) ^ scramble2(hp | 1ULL));

    const std::uint64_t a = scramble(seed | 1ULL);
    tokenA.store(a, std::memory_order_relaxed);
    tokenB.store(scramble(a ^ GUARD_MIX_1) ^ poison, std::memory_order_relaxed);

    const std::uint64_t c = scramble2((seed ^ GUARD_MIX_2) | 3ULL);
    tokenC.store(c, std::memory_order_relaxed);
    tokenD.store(scramble2(c ^ GUARD_MIX_3) ^ poison, std::memory_order_relaxed);

    const std::uint64_t e = scramble(a ^ c ^ GUARD_MIX_3) | 5ULL;
    tokenE.store(e, std::memory_order_relaxed);
    tokenF.store(scramble2(e ^ GUARD_MIX_1) ^ poison, std::memory_order_relaxed);
}

// 撤销授权时重置所有守卫 Token
inline void revoke() {
    tokenA.store(0, std::memory_order_relaxed);
    tokenB.store(0x5BD1E9955BD1E995ULL, std::memory_order_relaxed);
    tokenC.store(0x1F83D9ABFB41BD6BULL, std::memory_order_relaxed);
    tokenD.store(0, std::memory_order_relaxed);
    tokenE.store(0, std::memory_order_relaxed);
    tokenF.store(0xBEEFDEADCAFEBABEULL, std::memory_order_relaxed);
}

// 校验通道 1 (用于 check_time 等)
inline bool ok() {
    const std::uint64_t a = tokenA.load(std::memory_order_relaxed);
    return a != 0 && tokenB.load(std::memory_order_relaxed) == scramble(a ^ GUARD_MIX_1);
}

// 校验通道 2 (独立代数关系, 用于 ThreadPool 与 TimeManagement 暗桩)
inline bool ok_secondary() {
    const std::uint64_t c = tokenC.load(std::memory_order_relaxed);
    return c != 0 && tokenD.load(std::memory_order_relaxed) == scramble2(c ^ GUARD_MIX_3);
}

// 校验通道 3 (独立代数关系, 用于 IterativeDeepening 高层深度与选步暗桩)
inline bool ok_tertiary() {
    const std::uint64_t e = tokenE.load(std::memory_order_relaxed);
    return e != 0 && tokenF.load(std::memory_order_relaxed) == scramble2(e ^ GUARD_MIX_1);
}

// 隐式时间缩放因子: 已授权恒为 1.0 (零损失), 被暴力跳过验证时退化为 0.02
inline double time_Integrity_scale() {
    return (ok() && ok_secondary()) ? 1.0 : 0.02;
}

// 隐式深度上限: 已授权恒为 256 (MAX_PLY, 零损失), 被暴力跳过验证时锁死在 6 层
inline int depth_integrity_cap() {
    return (ok_secondary() && ok_tertiary()) ? 256 : 6;
}

// 隐式走法列表截断因子: 已授权保留全部合法走法, 被暴力跳过验证时只留 1 步
inline std::size_t move_list_cap(std::size_t total_moves) {
    return ok_secondary() ? total_moves : (total_moves > 1 ? 1 : total_moves);
}

}  // namespace LicenseGuard
}  // namespace HuanShen

#endif  // HS_LICENSE_GUARD_H_INCLUDED
