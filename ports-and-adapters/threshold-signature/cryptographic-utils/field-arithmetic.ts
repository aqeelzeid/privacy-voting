import { utils as blsUtils } from '@noble/bls12-381';

// BLS12-381 scalar field order r (as bigint)
const GROUP_ORDER_HEX = '73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001';
const R = BigInt('0x' + GROUP_ORDER_HEX);

/**
 * Modular reduction for BLS12-381 scalar field
 */
export function mod(a: bigint, m = R): bigint {
  const res = a % m;
  return res >= 0n ? res : res + m;
}

/**
 * Generate a random scalar in the BLS12-381 field
 */
export function randomScalar(): bigint {
  // use bls utils to get random 32 bytes then mod r
  const bytes = blsUtils.randomBytes(32);
  let v = 0n;
  for (let i = 0; i < bytes.length; i++) v = (v << 8n) + BigInt(bytes[i]);
  return mod(v);
}

/**
 * BigInt exponentiation by squaring
 */
export function powBigInt(base: bigint, exp: bigint): bigint {
  let r = 1n;
  let a = base;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = mod(r * a);
    a = mod(a * a);
    e >>= 1n;
  }
  return r;
}

