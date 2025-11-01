import { KEY_SCHEMAS } from '../../../account/namespace';
import { EncodedStringContainer, AESGCM256EncryptsRSAOAEP2048Key, HashedStringContainer } from '../../../account/account';

export interface PublicKeyContainer {
    format: typeof KEY_SCHEMAS.ENCODING.SPKI;
    key: EncodedStringContainer;
}

export type DKGSessionState =
  | 'INIT'
  | 'COMMITMENTS_PUBLISHED'
  | 'SHARES_SUBMITTED'
  | 'FINALIZED'
  | 'FAILED';

export interface DKGSession {
  sessionId: string;
  committeeId: string;
  threshold: number;
  totalParticipants: number;
  participants: string[];
  state: DKGSessionState;

  // Cryptographic data
  commitments: Record<string, string[]>; // participantId -> commitments
  encryptedShares: Record<string, Record<string, string>>; // senderId -> recipientId -> encrypted share
  groupPublicKey?: string;
  participantShares?: Record<string, string>; // optional, final verified shares

  progress: Record<
    string,
    {
      hasPublishedCommitment: boolean;
      hasSubmittedShares: boolean;
      hasFinalized: boolean;
    }
  >;

  history?: Array<{
    timestamp: string;
    participantId: string;
    action: 'START' | 'PUBLISH_COMMITMENT' | 'SUBMIT_SHARE' | 'FINALIZE';
    details?: Record<string, any>;
  }>;

  // Timing / audit
  createdAt: string;
  updatedAt: string;
  finalizedAt?: string;

  // Metadata
  scheme: 'BLS' | 'ECDSA' | 'ElGamal';
  mode: 'ONE_OVER_N' | 'MAJORITY' | 'ALL';
  metadata?: Record<string, any>;
}

/**
 * Calculate threshold based on mode and total participants
 * @param mode - The threshold mode
 * @param totalParticipants - Total number of participants
 * @returns The calculated threshold value
 */
export function calculateThreshold(mode: 'ONE_OVER_N' | 'MAJORITY' | 'ALL', totalParticipants: number): number {
    switch (mode) {
        case 'ONE_OVER_N':
            return 1;
        case 'MAJORITY':
            return Math.ceil(totalParticipants / 2) + 1;
        case 'ALL':
            return totalParticipants;
        default:
            throw new Error(`Unknown mode: ${mode}`);
    }
}

export interface StartDKGSessionParameters {
    sessionId: string;                     // unique ID for the session
    committeeId: string;                   // group this DKG belongs to
    threshold?: number;                    // minimum number of shares required (t) - calculated from mode if not provided
    totalParticipants: number;             // total number of members (n)
    participantIds: string[];              // list of member identifiers
    encryptionPublicKeys: Record<string, PublicKeyContainer>; // participantId -> encryption public key
    signingPublicKeys: Record<string, PublicKeyContainer>;    // participantId → signing public key (for verification)
    scheme: 'BLS' | 'ECDSA' | 'PAILLIER';  // which threshold scheme to use
    mode: 'ONE_OVER_N' | 'MAJORITY' | 'ALL'; // UX mode mapping (1/n, majority, n/n)
    metadata?: Record<string, any>;       // optional, like creation timestamp or creator's note
}

// Client-side helper types and errors
export interface ClientPolynomialData {
    commitments: string[];
    signature: string;
    selfShare: bigint;
    polynomial: bigint[];
}

export interface VerifiedSharesResult {
    verifiedShares: Record<string, bigint>;
    aggregatedShare: bigint;
    failedVerifications: string[];
}

export interface PublishCommitmentParameters {
    participantId: string;
    commitments: string[]; // array of public commitments (e.g., G^a_i for each coefficient)
    proofOfCorrectness?: string; // optional zero-knowledge proof (depends on scheme)
    signature: string; // signature over commitments for authenticity
  }

  export interface SubmitEncryptedShareParameters {
    participantId: string;
    encryptedShares: Record<string, string>; // recipientId → encrypted share
    signature: string; // signature over encryptedShares to ensure integrity
  }

  export interface FinalizeDKGSessionParameters {
    participantId: string;
    verifiedShares: Record<string, boolean>; // senderId → verified?
    localPrivateShare: string; // participant's computed private key share
    derivedGroupPublicKey: string; // computed group key
    proofOfInclusion?: string; // optional proof to show inclusion in group key computation
  }

