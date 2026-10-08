#include "crypto/secp256k1.h"

#include <string.h>

extern "C" {
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
}

#include "crypto/digest.h"
#include "crypto/secure.h"

namespace rockey {
namespace secp {
namespace {

// 曲线阶 n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
const uint8_t kOrderN[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                             0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
                             0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

// n/2 = 7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 5D576E73 57A4501D DFE92F46 681B20A0
const uint8_t kHalfN[32] = {0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4,
                            0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0};

mbedtls_ecp_group* Group() {
  static mbedtls_ecp_group grp;
  static bool inited = false;
  if (!inited) {
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
    inited = true;
  }
  return &grp;
}

void MpiFromBytes(mbedtls_mpi* x, const uint8_t* b, size_t len) {
  mbedtls_mpi_init(x);
  mbedtls_mpi_read_binary(x, b, len);
}

void MpiToBytes32(const mbedtls_mpi* x, uint8_t out[32]) {
  // mbedTLS 2.28：定长输出，左侧补零（大端）
  mbedtls_mpi_write_binary(x, out, 32);
}

bool MpiIsZero(const mbedtls_mpi* x) { return mbedtls_mpi_cmp_int(x, 0) == 0; }

bool InRange1N(const mbedtls_mpi* x) {
  mbedtls_mpi n;
  MpiFromBytes(&n, kOrderN, 32);
  bool ok = mbedtls_mpi_cmp_int(x, 1) >= 0 && mbedtls_mpi_cmp_mpi(x, &n) < 0;
  mbedtls_mpi_free(&n);
  return ok;
}

// 摘要按大端读入后对 n 取模（bits2int）
void DigestToZ(const uint8_t digest32[32], mbedtls_mpi* z) {
  mbedtls_mpi n;
  MpiFromBytes(z, digest32, 32);
  MpiFromBytes(&n, kOrderN, 32);
  mbedtls_mpi_mod_mpi(z, z, &n);
  mbedtls_mpi_free(&n);
}

// 点的仿射 X（不依赖 mbedtls 是否把结果归一化）
bool AffineX(const mbedtls_ecp_group* grp, const mbedtls_ecp_point* p, uint8_t out[32]) {
  if (mbedtls_ecp_is_zero(const_cast<mbedtls_ecp_point*>(p)) != 0) return false;
  mbedtls_mpi x;
  mbedtls_mpi_init(&x);
  int rc = mbedtls_mpi_copy(&x, &p->X);
  bool ok = false;
  if (rc == 0) {
    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    mbedtls_mpi_lset(&one, 1);
    if (mbedtls_mpi_cmp_mpi(&p->Z, &one) != 0) {
      mbedtls_mpi zi;
      mbedtls_mpi_init(&zi);
      if (mbedtls_mpi_inv_mod(&zi, &p->Z, &grp->P) == 0) {
        mbedtls_mpi_mul_mpi(&x, &x, &zi);
        mbedtls_mpi_mod_mpi(&x, &x, &grp->P);
        ok = true;
      }
      mbedtls_mpi_free(&zi);
    } else {
      ok = true;
    }
    mbedtls_mpi_free(&one);
  }
  if (ok) MpiToBytes32(&x, out);
  mbedtls_mpi_free(&x);
  return ok;
}

struct Rfc6979 {
  uint8_t k[32];
  uint8_t v[32];
  bool retry;

  void Init(const uint8_t priv[32], const uint8_t digest32[32]) {
    uint8_t x[32];
    memcpy(x, priv, 32);
    uint8_t h1[32];
    mbedtls_mpi z;
    mbedtls_mpi_init(&z);
    DigestToZ(digest32, &z);
    MpiToBytes32(&z, h1);
    mbedtls_mpi_free(&z);

    memset(k, 0x00, 32);
    memset(v, 0x01, 32);
    uint8_t msg[32 + 1 + 32 + 32];
    memcpy(msg, v, 32);
    msg[32] = 0x00;
    memcpy(msg + 33, x, 32);
    memcpy(msg + 65, h1, 32);
    digest::HmacSha256(k, 32, msg, sizeof(msg), k);
    digest::HmacSha256(k, 32, v, 32, v);
    msg[32] = 0x01;
    digest::HmacSha256(k, 32, msg, sizeof(msg), k);
    digest::HmacSha256(k, 32, v, 32, v);
    secure::Wipe(x, sizeof(x));
    secure::Wipe(h1, sizeof(h1));
    secure::Wipe(msg, sizeof(msg));
    retry = false;
  }

  void Next(uint8_t out[32]) {
    if (retry) {
      uint8_t msg[32 + 1];
      memcpy(msg, v, 32);
      msg[32] = 0x00;
      digest::HmacSha256(k, 32, msg, sizeof(msg), k);
      digest::HmacSha256(k, 32, v, 32, v);
      secure::Wipe(msg, sizeof(msg));
    }
    digest::HmacSha256(k, 32, v, 32, out);
    memcpy(v, out, 32);
    retry = true;
  }

  ~Rfc6979() {
    secure::Wipe(k, sizeof(k));
    secure::Wipe(v, sizeof(v));
  }
};

bool SignRaw(const uint8_t priv[32], const uint8_t digest32[32], uint8_t r[32], uint8_t s[32]) {
  if (!ValidatePriv(priv)) return false;
  mbedtls_ecp_group* grp = Group();
  mbedtls_mpi n, d, z, k, rMpi, sMpi, t;
  MpiFromBytes(&n, kOrderN, 32);
  MpiFromBytes(&d, priv, 32);
  mbedtls_mpi_init(&z);
  mbedtls_mpi_init(&k);
  mbedtls_mpi_init(&rMpi);
  mbedtls_mpi_init(&sMpi);
  mbedtls_mpi_init(&t);
  DigestToZ(digest32, &z);

  Rfc6979 nonce;
  nonce.Init(priv, digest32);

  bool ok = false;
  for (int attempt = 0; attempt < 64 && !ok; ++attempt) {
    uint8_t kb[32];
    nonce.Next(kb);
    mbedtls_mpi_read_binary(&k, kb, 32);
    if (MpiIsZero(&k) || mbedtls_mpi_cmp_mpi(&k, &n) >= 0) {
      secure::Wipe(kb, sizeof(kb));
      continue;
    }

    mbedtls_ecp_point R;
    mbedtls_ecp_point_init(&R);
    if (mbedtls_ecp_mul(grp, &R, &k, &grp->G, nullptr, nullptr) != 0 || !AffineX(grp, &R, kb)) {
      mbedtls_ecp_point_free(&R);
      secure::Wipe(kb, sizeof(kb));
      continue;
    }
    mbedtls_ecp_point_free(&R);

    mbedtls_mpi_read_binary(&rMpi, kb, 32);
    mbedtls_mpi_mod_mpi(&rMpi, &rMpi, &n);
    if (MpiIsZero(&rMpi)) {
      secure::Wipe(kb, sizeof(kb));
      continue;
    }

    // s = k^-1 * (z + r*d) mod n
    bool step = mbedtls_mpi_inv_mod(&t, &k, &n) == 0 &&
                mbedtls_mpi_mul_mpi(&sMpi, &rMpi, &d) == 0 &&
                mbedtls_mpi_add_mpi(&sMpi, &sMpi, &z) == 0 &&
                mbedtls_mpi_mul_mpi(&sMpi, &t, &sMpi) == 0;
    if (step) mbedtls_mpi_mod_mpi(&sMpi, &sMpi, &n);
    if (step && !MpiIsZero(&sMpi)) {
      MpiToBytes32(&rMpi, r);
      MpiToBytes32(&sMpi, s);
      ok = true;
    }
    secure::Wipe(kb, sizeof(kb));
  }

  mbedtls_mpi_free(&n);
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&z);
  mbedtls_mpi_free(&k);
  mbedtls_mpi_free(&rMpi);
  mbedtls_mpi_free(&sMpi);
  mbedtls_mpi_free(&t);
  return ok;
}

bool VerifyRaw(const uint8_t pubCompressed[33], const uint8_t digest32[32], const uint8_t r[32],
               const uint8_t s[32]) {
  mbedtls_ecp_group* grp = Group();
  mbedtls_ecp_point Q;
  mbedtls_ecp_point_init(&Q);
  if (mbedtls_ecp_point_read_binary(grp, &Q, pubCompressed, kPubCompressedLen) != 0 ||
      mbedtls_ecp_check_pubkey(grp, &Q) != 0) {
    mbedtls_ecp_point_free(&Q);
    return false;
  }

  mbedtls_mpi n, rMpi, sMpi, z, w, u1, u2;
  MpiFromBytes(&n, kOrderN, 32);
  MpiFromBytes(&rMpi, r, 32);
  MpiFromBytes(&sMpi, s, 32);
  mbedtls_mpi_init(&z);
  mbedtls_mpi_init(&w);
  mbedtls_mpi_init(&u1);
  mbedtls_mpi_init(&u2);
  DigestToZ(digest32, &z);

  bool ok = false;
  if (InRange1N(&rMpi) && InRange1N(&sMpi) && mbedtls_mpi_inv_mod(&w, &sMpi, &n) == 0) {
    mbedtls_mpi_mul_mpi(&u1, &z, &w);
    mbedtls_mpi_mod_mpi(&u1, &u1, &n);
    mbedtls_mpi_mul_mpi(&u2, &rMpi, &w);
    mbedtls_mpi_mod_mpi(&u2, &u2, &n);

    mbedtls_ecp_point P;
    mbedtls_ecp_point_init(&P);
    if (mbedtls_ecp_muladd(grp, &P, &u1, &grp->G, &u2, &Q) == 0) {
      uint8_t xb[32];
      if (AffineX(grp, &P, xb)) {
        mbedtls_mpi xr;
        MpiFromBytes(&xr, xb, 32);
        mbedtls_mpi_mod_mpi(&xr, &xr, &n);
        ok = mbedtls_mpi_cmp_mpi(&xr, &rMpi) == 0;
        mbedtls_mpi_free(&xr);
      }
      secure::Wipe(xb, sizeof(xb));
    }
    mbedtls_ecp_point_free(&P);
  }

  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&n);
  mbedtls_mpi_free(&rMpi);
  mbedtls_mpi_free(&sMpi);
  mbedtls_mpi_free(&z);
  mbedtls_mpi_free(&w);
  mbedtls_mpi_free(&u1);
  mbedtls_mpi_free(&u2);
  return ok;
}

}  // namespace

bool ValidatePriv(const uint8_t priv[kPrivLen]) {
  mbedtls_mpi d;
  MpiFromBytes(&d, priv, kPrivLen);
  bool ok = InRange1N(&d);
  mbedtls_mpi_free(&d);
  return ok;
}

bool PubkeyFromPriv(const uint8_t priv[kPrivLen], uint8_t pubCompressed[kPubCompressedLen]) {
  if (!ValidatePriv(priv)) return false;
  mbedtls_ecp_group* grp = Group();
  mbedtls_ecp_point Q;
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi d;
  MpiFromBytes(&d, priv, kPrivLen);
  int rc = mbedtls_ecp_mul(grp, &Q, &d, &grp->G, nullptr, nullptr);
  bool ok = false;
  if (rc == 0) {
    size_t olen = 0;
    rc = mbedtls_ecp_point_write_binary(grp, &Q, MBEDTLS_ECP_PF_COMPRESSED, &olen,
                                        pubCompressed, kPubCompressedLen);
    ok = (rc == 0 && olen == kPubCompressedLen);
  }
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
  return ok;
}

bool ValidatePubkey(const uint8_t pubCompressed[kPubCompressedLen]) {
  if (pubCompressed[0] != 0x02 && pubCompressed[0] != 0x03) return false;
  mbedtls_ecp_group* grp = Group();
  mbedtls_ecp_point Q;
  mbedtls_ecp_point_init(&Q);
  int rc = mbedtls_ecp_point_read_binary(grp, &Q, pubCompressed, kPubCompressedLen);
  if (rc == 0) rc = mbedtls_ecp_check_pubkey(grp, &Q);
  mbedtls_ecp_point_free(&Q);
  return rc == 0;
}

bool LowS(const uint8_t s[32], uint8_t out[32]) {
  mbedtls_mpi half, sMpi;
  MpiFromBytes(&half, kHalfN, 32);
  MpiFromBytes(&sMpi, s, 32);
  bool greater = mbedtls_mpi_cmp_mpi(&sMpi, &half) > 0;
  if (!greater) {
    memcpy(out, s, 32);
    mbedtls_mpi_free(&half);
    mbedtls_mpi_free(&sMpi);
    return true;
  }
  mbedtls_mpi n, diff;
  MpiFromBytes(&n, kOrderN, 32);
  mbedtls_mpi_init(&diff);
  mbedtls_mpi_sub_mpi(&diff, &n, &sMpi);
  MpiToBytes32(&diff, out);
  mbedtls_mpi_free(&n);
  mbedtls_mpi_free(&diff);
  mbedtls_mpi_free(&half);
  mbedtls_mpi_free(&sMpi);
  return true;
}

bool SignDer(const uint8_t priv[kPrivLen], const uint8_t digest32[32], uint8_t* derOut,
             size_t* derLen) {
  uint8_t r[32], s[32];
  if (!SignRaw(priv, digest32, r, s)) return false;
  LowS(s, s);
  size_t n = EncodeDer(r, s, derOut, kSigDerMax);
  secure::Wipe(r, sizeof(r));
  secure::Wipe(s, sizeof(s));
  if (n == 0) return false;
  *derLen = n;
  return true;
}

bool SignCompact(const uint8_t priv[kPrivLen], const uint8_t digest32[32],
                 uint8_t compactOut[kSigCompactLen]) {
  uint8_t r[32], s[32];
  if (!SignRaw(priv, digest32, r, s)) return false;
  LowS(s, s);
  memcpy(compactOut, r, 32);
  memcpy(compactOut + 32, s, 32);
  secure::Wipe(r, sizeof(r));
  secure::Wipe(s, sizeof(s));
  return true;
}

bool VerifyDer(const uint8_t pubCompressed[kPubCompressedLen], const uint8_t digest32[32],
               const uint8_t* der, size_t derLen) {
  uint8_t r[32], s[32];
  if (!DecodeDer(der, derLen, r, s)) return false;
  bool ok = VerifyRaw(pubCompressed, digest32, r, s);
  secure::Wipe(r, sizeof(r));
  secure::Wipe(s, sizeof(s));
  return ok;
}

bool VerifyCompact(const uint8_t pubCompressed[kPubCompressedLen], const uint8_t digest32[32],
                   const uint8_t compact[kSigCompactLen]) {
  return VerifyRaw(pubCompressed, digest32, compact, compact + 32);
}

namespace {

size_t EncodeInt(const uint8_t v[32], uint8_t* out) {
  size_t i = 0;
  while (i < 32 && v[i] == 0) i++;
  size_t bodyLen = 32 - i;
  uint8_t* p = out;
  *p++ = 0x02;
  if (v[i] & 0x80) {
    *p++ = static_cast<uint8_t>(bodyLen + 1);
    *p++ = 0x00;
  } else {
    *p++ = static_cast<uint8_t>(bodyLen);
  }
  memcpy(p, v + i, bodyLen);
  p += bodyLen;
  return static_cast<size_t>(p - out);
}

}  // namespace

size_t EncodeDer(const uint8_t r[32], const uint8_t s[32], uint8_t* out, size_t outCap) {
  if (outCap < kSigDerMax) return 0;
  uint8_t* p = out;
  *p++ = 0x30;
  size_t lenPos = static_cast<size_t>(p - out);
  *p++ = 0;
  size_t bodyStart = static_cast<size_t>(p - out);
  p += EncodeInt(r, p);
  p += EncodeInt(s, p);
  size_t bodyLen = static_cast<size_t>(p - out) - bodyStart;
  if (bodyLen > 0x7F) return 0;  // 签名不会超过 70 字节
  out[lenPos] = static_cast<uint8_t>(bodyLen);
  return static_cast<size_t>(p - out);
}

bool DecodeDer(const uint8_t* der, size_t derLen, uint8_t r[32], uint8_t s[32]) {
  if (derLen < 8 || derLen > kSigDerMax) return false;
  size_t i = 0;
  if (der[i++] != 0x30) return false;
  size_t len = der[i++];
  if (len & 0x80) return false;  // strict DER：签名不使用长格式长度
  if (len != derLen - 2) return false;
  auto readInt = [&](uint8_t out[32]) -> bool {
    if (i + 2 > derLen) return false;
    if (der[i++] != 0x02) return false;
    size_t l = der[i++];
    if (l == 0 || l > 33) return false;
    if (i + l > derLen) return false;
    if (der[i] == 0x00 && l > 1 && der[i + 1] & 0x80) {
      // 唯一允许的前导 0：正数溢出到最高位
      i++;
      l -= 1;
    }
    if (l > 32) return false;
    if (der[i] & 0x80) return false;  // 负数不接受
    if (der[i] == 0x00) return false;  // 非最小编码
    memset(out, 0, 32);
    memcpy(out + (32 - l), der + i, l);
    i += l;
    return true;
  };
  if (!readInt(r)) return false;
  if (!readInt(s)) return false;
  if (i != derLen) return false;
  return true;
}

}  // namespace secp
}  // namespace rockey