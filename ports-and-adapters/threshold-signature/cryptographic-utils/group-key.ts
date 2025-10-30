import { PointG1 } from '@noble/bls12-381';
import { pointG1ToHex } from './conversion';

/**
 * Compute the group public key from all participant commitments
 */
export function computeGroupPublicKey(allCommitments: Record<string, string[]>): string {
  let groupKey = PointG1.ZERO;

  for (const participantCommitments of Object.values(allCommitments)) {
    if (participantCommitments.length > 0) {
      const commitment = PointG1.fromHex(participantCommitments[0]);
      groupKey = groupKey.add(commitment);
    }
  }

  return pointG1ToHex(groupKey);
}

/**
 * Aggregate shares from all participants to get the private key share
 */
export function aggregateShares(shares: bigint[]): bigint {
  return shares.reduce((sum, share) => sum + share, 0n);
}

