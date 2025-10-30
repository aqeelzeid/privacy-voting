import { Result } from '../../error';
import { KEY_SCHEMAS } from '../../account/namespace';
import { EncodedStringContainer, AESGCM256EncryptsRSAOAEP2048Key, HashedStringContainer } from '../../account/account';

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
    scheme: 'BLS' | 'ECDSA' | 'ElGamal';  // which threshold scheme to use
    mode: 'ONE_OVER_N' | 'MAJORITY' | 'ALL'; // UX mode mapping (1/n, majority, n/n)
    metadata?: Record<string, any>;       // optional, like creation timestamp or creator’s note
}


export interface StartDKGSessionError {
    code: "UNKNOWN_ERROR"
        | "INVALID_PARAMETERS"
        | "DUPLICATE_SESSION"
        | "INVALID_PARTICIPANTS"
        | "INVALID_THRESHOLD"
        | "UNSUPPORTED_SCHEME"
        | "KEY_FORMAT_ERROR"
        | "VALIDATION_ERROR";
    message: string;
    error?: unknown;
}

export interface PublishCommitmentError {
    code: "UNKNOWN_ERROR"
        | "INVALID_STATE"
        | "PARTICIPANT_NOT_FOUND"
        | "INVALID_COMMITMENTS"
        | "COMMITMENT_VERIFICATION_FAILED"
        | "SIGNATURE_VERIFICATION_FAILED"
        | "DUPLICATE_COMMITMENT"
        | "CRYPT_ERROR"
        | "KEY_FORMAT_ERROR";
    message: string;
    error?: unknown;
}

export interface SubmitEncryptedShareError {
    code: "UNKNOWN_ERROR"
        | "INVALID_STATE"
        | "PARTICIPANT_NOT_FOUND"
        | "MISSING_COMMITMENTS"
        | "ENCRYPTION_FAILED"
        | "SIGNATURE_VERIFICATION_FAILED"
        | "INVALID_SHARES"
        | "DUPLICATE_SHARES"
        | "CRYPT_ERROR"
        | "KEY_FORMAT_ERROR";
    message: string;
    error?: unknown;
}

export interface FinalizeDKGSessionError {
    code: "UNKNOWN_ERROR"
        | "INVALID_STATE"
        | "PARTICIPANT_NOT_FOUND"
        | "MISSING_COMMITMENTS"
        | "MISSING_SHARES"
        | "SHARE_VERIFICATION_FAILED"
        | "GROUP_KEY_COMPUTATION_FAILED"
        | "SIGNATURE_VERIFICATION_FAILED"
        | "INSUFFICIENT_PARTICIPANTS"
        | "CRYPT_ERROR"
        | "VALIDATION_ERROR";
    message: string;
    error?: unknown;
}

export interface GetDKGSessionError {
    code: "UNKNOWN_ERROR"
        | "SESSION_NOT_FOUND"
        | "ACCESS_DENIED"
        | "VALIDATION_ERROR";
    message: string;
    error?: unknown;
}

// Client-side helper types and errors
export interface ClientPolynomialData {
    commitments: string[];
    signature: string;
    selfShare: bigint;
    polynomial: bigint[];
}

export interface GeneratePolynomialError {
    code: "UNKNOWN_ERROR"
        | "KEY_DECRYPTION_FAILED"
        | "SIGNING_FAILED"
        | "VALIDATION_ERROR";
    message: string;
    error?: unknown;
}

export interface EncryptSharesError {
    code: "UNKNOWN_ERROR"
        | "ENCRYPTION_FAILED"
        | "KEY_FORMAT_ERROR"
        | "VALIDATION_ERROR";
    message: string;
    error?: unknown;
}

export interface VerifiedSharesResult {
    verifiedShares: Record<string, bigint>;
    aggregatedShare: bigint;
    failedVerifications: string[];
}

export interface VerifySharesError {
    code: "UNKNOWN_ERROR"
        | "DECRYPTION_FAILED"
        | "VERIFICATION_FAILED"
        | "KEY_DECRYPTION_FAILED"
        | "VALIDATION_ERROR";
    message: string;
    error?: unknown;
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


export interface DistributedKeyGenerationPort {
      startDKGSession(
        params: StartDKGSessionParameters
      ): Promise<Result<DKGSession, StartDKGSessionError>>;

      publishCommitment(
        session: DKGSession,
        params: PublishCommitmentParameters
      ): Promise<Result<DKGSession, PublishCommitmentError>>;

      submitEncryptedShare(
        session: DKGSession,
        params: SubmitEncryptedShareParameters
      ): Promise<Result<DKGSession, SubmitEncryptedShareError>>;

      finalizeDKGSession(
        session: DKGSession,
        params: FinalizeDKGSessionParameters
      ): Promise<Result<DKGSession, FinalizeDKGSessionError>>;

      // Client-side helper methods
      generatePolynomialAndCommitments(
        threshold: number,
        participantIndex: number,
        privateKey: AESGCM256EncryptsRSAOAEP2048Key,
        kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer }
      ): Promise<Result<ClientPolynomialData, GeneratePolynomialError>>;

      encryptSharesForParticipants(
        polynomial: bigint[],
        participantIndex: number,
        recipients: Record<string, { index: number; publicKey: PublicKeyContainer }>
      ): Promise<Result<Record<string, string>, EncryptSharesError>>;

      verifyAndDecryptReceivedShares(
        encryptedShares: Record<string, string>,
        commitments: Record<string, string[]>,
        participantIndex: number,
        privateKey: AESGCM256EncryptsRSAOAEP2048Key,
        kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer }
      ): Promise<Result<VerifiedSharesResult, VerifySharesError>>;
}

// export interface ThresholdSignaturePort {
//     createPartialSignature(createPartialSignatureParameters: CreatePartialSignatureParameters): Promise<Result<CreatePartialSignatureResult, CreatePartialSignatureError>>;
//     combinePartialSignatures(combinePartialSignaturesParameters: CombinePartialSignaturesParameters): Promise<Result<CombinePartialSignaturesResult, CombinePartialSignaturesError>>;
//     verifyGroupSignature(verifyGroupSignatureParameters: VerifyGroupSignatureParameters): Promise<Result<VerifyGroupSignatureResult, VerifyGroupSignatureError>>;
// }


export interface ThresholdKeyPort extends DistributedKeyGenerationPort /*,ThresholdSignaturePort */ {}