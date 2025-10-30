import { Result } from "../../../../error";
import { DistributedKeyGenerationPort, DKGSession, StartDKGSessionError, StartDKGSessionParameters, PublishCommitmentError, PublishCommitmentParameters, SubmitEncryptedShareError, SubmitEncryptedShareParameters, FinalizeDKGSessionError, FinalizeDKGSessionParameters, ClientPolynomialData, GeneratePolynomialError, EncryptSharesError, VerifiedSharesResult, VerifySharesError, PublicKeyContainer } from "../port";
import { CryptographicPort } from "../../../cryptographic-port";
import { AESGCM256EncryptsRSAOAEP2048Key, EncodedStringContainer, HashedStringContainer } from "../../../../account/account";
import { startDKGSession } from "./session-management";
import { publishCommitment } from "./commitment-management";
import { submitEncryptedShare, finalizeDKGSession } from "./share-management";
import { generatePolynomialAndCommitments, encryptSharesForParticipants, verifyAndDecryptReceivedShares } from "./client-helpers";

export class DistributedKeyGenerationAdapter implements DistributedKeyGenerationPort {
    private sessions: Map<string, DKGSession> = new Map();

    constructor(private cryptographicPort: CryptographicPort) {}

    async startDKGSession(params: StartDKGSessionParameters): Promise<Result<DKGSession, StartDKGSessionError>> {
        return startDKGSession(this.sessions, params);
    }

    async publishCommitment(session: DKGSession, params: PublishCommitmentParameters): Promise<Result<DKGSession, PublishCommitmentError>> {
        return publishCommitment(this.sessions, session, params);
    }

    async submitEncryptedShare(session: DKGSession, params: SubmitEncryptedShareParameters): Promise<Result<DKGSession, SubmitEncryptedShareError>> {
        return submitEncryptedShare(this.sessions, session, params);
    }

    async finalizeDKGSession(session: DKGSession, params: FinalizeDKGSessionParameters): Promise<Result<DKGSession, FinalizeDKGSessionError>> {
        return finalizeDKGSession(this.sessions, session, params);
    }

    async generatePolynomialAndCommitments(
        threshold: number,
        participantIndex: number,
        privateKey: AESGCM256EncryptsRSAOAEP2048Key,
        kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer }
    ): Promise<Result<ClientPolynomialData, GeneratePolynomialError>> {
        return generatePolynomialAndCommitments(threshold, participantIndex, privateKey, kek, this.cryptographicPort);
    }

    async encryptSharesForParticipants(
        polynomial: bigint[],
        participantIndex: number,
        recipients: Record<string, { index: number; publicKey: PublicKeyContainer }>
    ): Promise<Result<Record<string, string>, EncryptSharesError>> {
        return encryptSharesForParticipants(polynomial, participantIndex, recipients, this.cryptographicPort);
    }

    async verifyAndDecryptReceivedShares(
        encryptedShares: Record<string, string>,
        commitments: Record<string, string[]>,
        participantIndex: number,
        privateKey: AESGCM256EncryptsRSAOAEP2048Key,
        kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer }
    ): Promise<Result<VerifiedSharesResult, VerifySharesError>> {
        return verifyAndDecryptReceivedShares(encryptedShares, commitments, participantIndex, privateKey, kek, this.cryptographicPort);
    }
}
