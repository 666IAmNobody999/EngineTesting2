/*
  幻神引擎 授权状态守卫 (轻量 header, 不含 windows.h, 可安全被 search.cpp 引用)

  授权验证成功时由 hwid_lock.h 写入一对互相校验的 token;
  搜索线程在 check_time() 中定期检查, 若 token 不一致 (例如有人只把 Engine::go
  里的授权判断 patch 掉) 就立即停止搜索。这只是增加破解难度的第二道关卡。
*/

#ifndef HS_LICENSE_GUARD_H_INCLUDED
#define HS_LICENSE_GUARD_H_INCLUDED

#include <atomic>
#include <cstdint>

namespace HuanShen {
namespace LicenseGuard {

inline std::atomic<std::uint64_t> tokenA{0};
inline std::atomic<std::uint64_t> tokenB{0x5bd1e9955bd1e995ULL};

constexpr std::uint64_t GUARD_MIX = 0x9E3779B97F4A7C15ULL;

inline std::uint64_t scramble(std::uint64_t z) {
    z = (z ^ (z >> 31)) * 0xD6E8FEB86659FD93ULL;
    z = (z ^ (z >> 29)) * 0xA5CB9243F5E1C1EBULL;
    return z ^ (z >> 32);
}

inline void grant(std::uint64_t seed) {
    const std::uint64_t a = scramble(seed | 1ULL);
    tokenA.store(a, std::memory_order_relaxed);
    tokenB.store(scramble(a ^ GUARD_MIX), std::memory_order_relaxed);
}

inline void revoke() {
    tokenA.store(0, std::memory_order_relaxed);
    tokenB.store(0x5bd1e9955bd1e995ULL, std::memory_order_relaxed);
}

inline bool ok() {
    const std::uint64_t a = tokenA.load(std::memory_order_relaxed);
    return a != 0 && tokenB.load(std::memory_order_relaxed) == scramble(a ^ GUARD_MIX);
}

}  // namespace LicenseGuard
}  // namespace HuanShen

#endif  // HS_LICENSE_GUARD_H_INCLUDED
