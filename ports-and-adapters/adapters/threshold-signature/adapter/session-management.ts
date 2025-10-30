import { Result, err, ok } from "../../../../error";
import { DistributedKeyGenerationPort, DKGSession, StartDKGSessionError, StartDKGSessionParameters, PublicKeyContainer, calculateThreshold } from "../port";
import { spkiPublicKeyToBytes } from "../cryptographic-utils";

export function startDKGSession(
    sessions: Map<string, DKGSession>,
    params: StartDKGSessionParameters
): Promise<Result<DKGSession, StartDKGSessionError>> {
    try {
        // Validate parameters
        if (!params.sessionId || !params.committeeId) {
            return Promise.resolve(err({
                code: "INVALID_PARAMETERS",
                message: "sessionId and committeeId are required"
            }));
        }

        if (params.totalParticipants <= 0) {
            return Promise.resolve(err({
                code: "INVALID_PARTICIPANTS",
                message: "totalParticipants must be greater than 0"
            }));
        }

        // Calculate threshold from mode if not provided
        const threshold = params.threshold ?? calculateThreshold(params.mode, params.totalParticipants);

        // Validate threshold is within valid range
        if (threshold <= 0 || threshold > params.totalParticipants) {
            return Promise.resolve(err({
                code: "INVALID_THRESHOLD",
                message: `threshold must be between 1 and ${params.totalParticipants}, got ${threshold} for mode ${params.mode}`
            }));
        }

        if (params.participantIds.length !== params.totalParticipants) {
            return Promise.resolve(err({
                code: "INVALID_PARTICIPANTS",
                message: `participantIds length (${params.participantIds.length}) must match totalParticipants (${params.totalParticipants})`
            }));
        }

        if (params.participantIds.length !== Object.keys(params.encryptionPublicKeys).length ||
            params.participantIds.length !== Object.keys(params.signingPublicKeys).length) {
            return Promise.resolve(err({
                code: "INVALID_PARTICIPANTS",
                message: "encryption and signing public keys must be provided for all participants"
            }));
        }

        // Check for duplicate session
        if (sessions.has(params.sessionId)) {
            return Promise.resolve(err({
                code: "DUPLICATE_SESSION",
                message: `Session ${params.sessionId} already exists`
            }));
        }

        // Validate scheme support
        if (params.scheme !== 'BLS') {
            return Promise.resolve(err({
                code: "UNSUPPORTED_SCHEME",
                message: `Scheme ${params.scheme} is not supported. Only BLS is currently supported.`
            }));
        }

        // Validate key formats
        try {
            for (const participantId of params.participantIds) {
                const encKey = params.encryptionPublicKeys[participantId];
                const signKey = params.signingPublicKeys[participantId];

                if (!encKey || !signKey) {
                    return Promise.resolve(err({
                        code: "KEY_FORMAT_ERROR",
                        message: `Missing keys for participant ${participantId}`
                    }));
                }

                // Validate encryption key (should be RSA public key in SPKI format)
                spkiPublicKeyToBytes(encKey);

                // Validate signing key format
                if (signKey.format !== 'https://abiogenesys.io/keys/encoding/spki') {
                    return Promise.resolve(err({
                        code: "KEY_FORMAT_ERROR",
                        message: `Invalid signing key format for participant ${participantId}`
                    }));
                }
            }
        } catch (error) {
            return Promise.resolve(err({
                code: "KEY_FORMAT_ERROR",
                message: `Invalid key format: ${error instanceof Error ? error.message : 'Unknown error'}`,
                error
            }));
        }

        // Create session
        const now = new Date().toISOString();
        const session: DKGSession = {
            sessionId: params.sessionId,
            committeeId: params.committeeId,
            threshold: threshold,
            totalParticipants: params.totalParticipants,
            participants: params.participantIds,
            state: 'INIT',
            commitments: {},
            encryptedShares: {},
            progress: {},
            createdAt: now,
            updatedAt: now,
            scheme: params.scheme,
            mode: params.mode,
            metadata: params.metadata,
            history: [{
                timestamp: now,
                participantId: 'system',
                action: 'START',
                details: { threshold: threshold, totalParticipants: params.totalParticipants, mode: params.mode }
            }]
        };

        // Initialize progress tracking
        for (const participantId of params.participantIds) {
            session.progress[participantId] = {
                hasPublishedCommitment: false,
                hasSubmittedShares: false,
                hasFinalized: false
            };
        }

        // Store session
        sessions.set(params.sessionId, session);

        return Promise.resolve(ok(session));
    } catch (error) {
        return Promise.resolve(err({
            code: "UNKNOWN_ERROR",
            message: `Failed to start DKG session: ${error instanceof Error ? error.message : 'Unknown error'}`,
            error
        }));
    }
}
