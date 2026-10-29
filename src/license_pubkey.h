/*
  幻神引擎 授权公钥 (由 hs_keygen genkey 自动生成, 请勿手动修改)

  !! 这里是占位档 !!
  请先执行:  hs_keygen genkey
  它会生成 private_key.hex (私钥, 绝不能外流/上传) 以及新的 license_pubkey.h,
  用新档覆盖本档后再编译引擎。

  公钥可以公开 (提交到 git 也没问题), 只靠公钥无法产生授权码。
*/

#ifndef HS_LICENSE_PUBKEY_H_INCLUDED
#define HS_LICENSE_PUBKEY_H_INCLUDED

#include <cstdint>

namespace HuanShen {
namespace License {

// public key = PUBKEY_PART_A XOR PUBKEY_PART_B
inline constexpr std::uint8_t PUBKEY_PART_A[32] = {0};
inline constexpr std::uint8_t PUBKEY_PART_B[32] = {0};

}  // namespace License
}  // namespace HuanShen

#endif  // HS_LICENSE_PUBKEY_H_INCLUDED
