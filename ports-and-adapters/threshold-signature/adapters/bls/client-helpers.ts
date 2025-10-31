import { Result, err, ok } from "../../../../error";
import { ClientPolynomialData, GeneratePolynomialError, EncryptSharesError, VerifiedSharesResult, VerifySharesError, PublicKeyContainer } from "../../port";
import { randomPolynomial, computeCommitments, evalPoly, encryptShareWithRSA, decryptShareWithRSA, signCommitments, commitmentCheck, aggregateShares } from "../../cryptographic-utils";
import { CryptographicPort } from "../../../cryptographic/port";
import { AESGCM256EncryptsRSAOAEP2048Key, EncodedStringContainer, HashedStringContainer } from "../../../../account/account";

export async function generatePolynomialAndCommitments(
    threshold: number,
    participantIndex: number,
    privateKey: AESGCM256EncryptsRSAOAEP2048Key,
    kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer },
    cryptographicPort: CryptographicPort
): Promise<Result<ClientPolynomialData, GeneratePolynomialError>> {
    try {
        // Generate random polynomial
        const polynomial = randomPolynomial(threshold - 1);

        // Compute Feldman commitments
        const commitments = computeCommitments(polynomial);

        // Sign the commitments
        const signResult = await signCommitments(commitments, privateKey, kek, cryptographicPort);
        if (!signResult.ok) {
            return err({
                code: "SIGNING_FAILED",
                message: "Failed to sign commitments",
                error: signResult.error
            });
        }

        // Compute self-share
        const selfShare = evalPoly(polynomial, BigInt(participantIndex));

        return ok({
            commitments,
            signature: signResult.value,
            selfShare,
            polynomial
        });
    } catch (error) {
        return err({
            code: "UNKNOWN_ERROR",
            message: `Failed to generate polynomial and commitments: ${error instanceof Error ? error.message : 'Unknown error'}`,
            error
        });
    }
}

export async function encryptSharesForParticipants(
    polynomial: bigint[],
    participantIndex: number,
    recipients: Record<string, { index: number; publicKey: PublicKeyContainer }>,
    cryptographicPort: CryptographicPort
): Promise<Result<Record<string, string>, EncryptSharesError>> {
    try {
        const encryptedShares: Record<string, string> = {};

        for (const [recipientId, recipient] of Object.entries(recipients)) {
            // Evaluate polynomial at recipient's index
            const shareValue = evalPoly(polynomial, BigInt(recipient.index));

            // Encrypt share with recipient's public key
            const encryptResult = await encryptShareWithRSA(shareValue, recipient.publicKey, cryptographicPort);
            if (!encryptResult.ok) {
                return err({
                    code: "ENCRYPTION_FAILED",
                    message: `Failed to encrypt share for ${recipientId}`,
                    error: encryptResult.error
                });
            }

            encryptedShares[recipientId] = encryptResult.value;
        }

        return ok(encryptedShares);
    } catch (error) {
        return err({
            code: "UNKNOWN_ERROR",
            message: `Failed to encrypt shares: ${error instanceof Error ? error.message : 'Unknown error'}`,
            error
        });
    }
}

export async function verifyAndDecryptReceivedShares(
    encryptedShares: Record<string, string>,
    commitments: Record<string, string[]>,
    participantIndex: number,
    privateKey: AESGCM256EncryptsRSAOAEP2048Key,
    kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer },
    cryptographicPort: CryptographicPort
): Promise<Result<VerifiedSharesResult, VerifySharesError>> {
    try {
        const verifiedShares: Record<string, bigint> = {};
        const failedVerifications: string[] = [];

        for (const [senderId, encryptedShare] of Object.entries(encryptedShares)) {
            try {
                // Decrypt the share
                const decryptResult = await decryptShareWithRSA(encryptedShare, privateKey, kek, cryptographicPort);
                if (!decryptResult.ok) {
                    failedVerifications.push(`${senderId}: decryption failed`);
                    continue;
                }

                const shareValue = decryptResult.value;

                // Verify against sender's commitments
                const senderCommitments = commitments[senderId];
                if (!senderCommitments) {
                    failedVerifications.push(`${senderId}: missing commitments`);
                    continue;
                }

                const isValid = commitmentCheck(senderCommitments, shareValue, BigInt(participantIndex));
                if (!isValid) {
                    failedVerifications.push(`${senderId}: commitment verification failed`);
                    continue;
                }

                verifiedShares[senderId] = shareValue;
            } catch (error) {
                failedVerifications.push(`${senderId}: ${error instanceof Error ? error.message : 'unknown error'}`);
            }
        }

        // Aggregate verified shares
        const shareValues = Object.values(verifiedShares);
        const aggregatedShare = shareValues.length > 0 ? aggregateShares(shareValues) : 0n;

        return ok({
            verifiedShares,
            aggregatedShare,
            failedVerifications
        });
    } catch (error) {
        return err({
            code: "UNKNOWN_ERROR",
            message: `Failed to verify and decrypt shares: ${error instanceof Error ? error.message : 'Unknown error'}`,
            error
        });
    }
}
