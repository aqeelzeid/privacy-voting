import { PointG1 } from '@noble/bls12-381';
import { powBigInt } from './field-arithmetic';

/**
 * Compute Feldman commitments for polynomial coefficients
 */
export function computeCommitments(coeffs: bigint[]): string[] {
  // commitments = [g^a0, g^a1, ...] on G1, encoded as hex
  return coeffs.map((a) => PointG1.BASE.multiply(a).toHex(true));
}

/**
 * Verify a share against commitments using Feldman verification
 */
export function commitmentCheck(commitmentsHex: string[], share: bigint, receiverIndex: bigint): boolean {
  // check: g^{share} == prod_{k=0..t-1} commitments[k]^{index^k}
  // convert commitments back to PointG1
  let rhs = PointG1.ZERO;
  for (let k = 0; k < commitmentsHex.length; k++) {
    const Ck = PointG1.fromHex(commitmentsHex[k]);
    const power = powBigInt(receiverIndex, BigInt(k));
    rhs = rhs.add(Ck.multiply(power));
  }

  const lhs = PointG1.BASE.multiply(share);
  return lhs.equals(rhs);
}

