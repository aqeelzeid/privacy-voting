import { Result } from '../../../error';
import {
    DKGSession,
    StartDKGSessionParameters,
    PublishCommitmentParameters,
    SubmitEncryptedShareParameters,
    FinalizeDKGSessionParameters,
    ClientPolynomialData,
    VerifiedSharesResult,
    PublicKeyContainer
} from './types';
import {
    StartDKGSessionError,
    PublishCommitmentError,
    SubmitEncryptedShareError,
    FinalizeDKGSessionError,
    GeneratePolynomialError,
    EncryptSharesError,
    VerifySharesError
} from './errors';
import { AESGCM256EncryptsRSAOAEP2048Key, HashedStringContainer, EncodedStringContainer } from '../../../account/account';

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
