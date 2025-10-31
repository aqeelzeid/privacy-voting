import { Result, err, ok } from "../../../../error";
import { DKGSession, SubmitEncryptedShareError, SubmitEncryptedShareParameters, FinalizeDKGSessionError, FinalizeDKGSessionParameters } from "../../port";
import { computeGroupPublicKey } from "../../cryptographic-utils";

export function submitEncryptedShare(
    sessions: Map<string, DKGSession>,
    session: DKGSession,
    params: SubmitEncryptedShareParameters
): Promise<Result<DKGSession, SubmitEncryptedShareError>> {
    try {
        // Get the current session state
        const currentSession = sessions.get(session.sessionId);
        if (!currentSession) {
            return Promise.resolve(err({
                code: "UNKNOWN_ERROR",
                message: `Session ${session.sessionId} not found`
            }));
        }

        // Validate session state
        if (currentSession.state !== 'COMMITMENTS_PUBLISHED' && currentSession.state !== 'SHARES_SUBMITTED') {
            return Promise.resolve(err({
                code: "INVALID_STATE",
                message: `Cannot submit shares in state ${currentSession.state}`
            }));
        }

        // Validate participant
        if (!currentSession.participants.includes(params.participantId)) {
            return Promise.resolve(err({
                code: "PARTICIPANT_NOT_FOUND",
                message: `Participant ${params.participantId} is not part of this session`
            }));
        }

        // Check if all commitments are available
        const allCommitmentsPublished = Object.values(currentSession.progress).every(p => p.hasPublishedCommitment);
        if (!allCommitmentsPublished) {
            return Promise.resolve(err({
                code: "MISSING_COMMITMENTS",
                message: "Cannot submit shares until all participants have published commitments"
            }));
        }

        // Check if participant already submitted shares
        if (currentSession.progress[params.participantId].hasSubmittedShares) {
            return Promise.resolve(err({
                code: "DUPLICATE_SHARES",
                message: `Participant ${params.participantId} has already submitted shares`
            }));
        }

        // Validate share parameters
        if (!params.encryptedShares || Object.keys(params.encryptedShares).length === 0) {
            return Promise.resolve(err({
                code: "INVALID_SHARES",
                message: "Encrypted shares object cannot be empty"
            }));
        }

        // Shares should be provided for all other participants
        const expectedRecipients = currentSession.participants.filter(p => p !== params.participantId);
        const providedRecipients = Object.keys(params.encryptedShares);
        if (providedRecipients.length !== expectedRecipients.length ||
            !expectedRecipients.every(r => providedRecipients.includes(r))) {
            return Promise.resolve(err({
                code: "INVALID_SHARES",
                message: `Shares must be provided for all other participants: ${expectedRecipients.join(', ')}`
            }));
        }

        // Verify signature if provided (signature is now part of the share submission data)
        // In the client-side implementation, encrypted shares are signed by the client
        // For now, we assume they are valid (signature verification will be done by clients)

        // Use the encrypted shares provided by the client (generated and encrypted client-side)
        const sharesToStore = params.encryptedShares;

        // Store encrypted shares
        currentSession.encryptedShares[params.participantId] = sharesToStore;
        currentSession.progress[params.participantId].hasSubmittedShares = true;

        // Add to history
        currentSession.history!.push({
            timestamp: new Date().toISOString(),
            participantId: params.participantId,
            action: 'SUBMIT_SHARE',
            details: { recipientCount: Object.keys(sharesToStore).length }
        });

        // Update session state if all participants have submitted shares
        const allSubmitted = Object.values(currentSession.progress).every(p => p.hasSubmittedShares);
        if (allSubmitted && currentSession.state === 'COMMITMENTS_PUBLISHED') {
            currentSession.state = 'SHARES_SUBMITTED';
        }

        currentSession.updatedAt = new Date().toISOString();

        // Update stored session
        sessions.set(session.sessionId, currentSession);

        return Promise.resolve(ok(currentSession));
    } catch (error) {
        return Promise.resolve(err({
            code: "UNKNOWN_ERROR",
            message: `Failed to submit encrypted share: ${error instanceof Error ? error.message : 'Unknown error'}`,
            error
        }));
    }
}

export function finalizeDKGSession(
    sessions: Map<string, DKGSession>,
    session: DKGSession,
    params: FinalizeDKGSessionParameters
): Promise<Result<DKGSession, FinalizeDKGSessionError>> {
    try {
        // Get the current session state
        const currentSession = sessions.get(session.sessionId);
        if (!currentSession) {
            return Promise.resolve(err({
                code: "UNKNOWN_ERROR",
                message: `Session ${session.sessionId} not found`
            }));
        }

        // Validate session state
        if (currentSession.state !== 'SHARES_SUBMITTED') {
            return Promise.resolve(err({
                code: "INVALID_STATE",
                message: `Cannot finalize session in state ${currentSession.state}`
            }));
        }

        // Validate participant
        if (!currentSession.participants.includes(params.participantId)) {
            return Promise.resolve(err({
                code: "PARTICIPANT_NOT_FOUND",
                message: `Participant ${params.participantId} is not part of this session`
            }));
        }

        // Check if all shares are available
        const allSharesSubmitted = Object.values(currentSession.progress).every(p => p.hasSubmittedShares);
        if (!allSharesSubmitted) {
            return Promise.resolve(err({
                code: "MISSING_SHARES",
                message: "Cannot finalize until all participants have submitted shares"
            }));
        }

        // Check if participant already finalized
        if (currentSession.progress[params.participantId].hasFinalized) {
            return Promise.resolve(err({
                code: "VALIDATION_ERROR",
                message: `Participant ${params.participantId} has already finalized`
            }));
        }

        // Validate parameters
        if (!params.verifiedShares) {
            return Promise.resolve(err({
                code: "VALIDATION_ERROR",
                message: "verifiedShares parameter is required"
            }));
        }

        if (!params.localPrivateShare) {
            return Promise.resolve(err({
                code: "VALIDATION_ERROR",
                message: "localPrivateShare parameter is required"
            }));
        }

        if (!params.derivedGroupPublicKey) {
            return Promise.resolve(err({
                code: "VALIDATION_ERROR",
                message: "derivedGroupPublicKey parameter is required"
            }));
        }

        // In the client-side implementation, share verification and aggregation
        // is done client-side. The server only verifies that:
        // 1. All commitments are present
        // 2. All encrypted shares are present
        // 3. The group public key computation is correct

        // Verify that all commitments are present
        const allCommitmentsPresent = Object.keys(currentSession.commitments).length === currentSession.totalParticipants;
        if (!allCommitmentsPresent) {
            return Promise.resolve(err({
                code: "MISSING_COMMITMENTS",
                message: "Not all participants have published commitments"
            }));
        }

        // Verify that all encrypted shares are present
        const allSharesPresent = Object.keys(currentSession.encryptedShares).length === currentSession.totalParticipants;
        if (!allSharesPresent) {
            return Promise.resolve(err({
                code: "MISSING_SHARES",
                message: "Not all participants have submitted encrypted shares"
            }));
        }

        // Compute group public key from all commitments
        const groupPublicKey = computeGroupPublicKey(currentSession.commitments);

        // Verify that the provided group public key matches our computation
        if (params.derivedGroupPublicKey !== groupPublicKey) {
            return Promise.resolve(err({
                code: "GROUP_KEY_COMPUTATION_FAILED",
                message: "Provided group public key does not match computed value"
            }));
        }

        // Store the participant's private share (computed client-side) and group key
        if (!currentSession.participantShares) {
            currentSession.participantShares = {};
        }
        currentSession.participantShares[params.participantId] = params.localPrivateShare;
        currentSession.groupPublicKey = groupPublicKey;
        currentSession.progress[params.participantId].hasFinalized = true;

        // Add to history
        currentSession.history!.push({
            timestamp: new Date().toISOString(),
            participantId: params.participantId,
            action: 'FINALIZE',
            details: {
                verifiedSharesCount: params.verifiedShares ? Object.keys(params.verifiedShares).length : 0
            }
        });

        // Check if all participants have finalized
        const allFinalized = Object.values(currentSession.progress).every(p => p.hasFinalized);
        if (allFinalized) {
            currentSession.state = 'FINALIZED';
            currentSession.finalizedAt = new Date().toISOString();
        }

        currentSession.updatedAt = new Date().toISOString();

        // Update stored session
        sessions.set(session.sessionId, currentSession);

        return Promise.resolve(ok(currentSession));
    } catch (error) {
        return Promise.resolve(err({
            code: "UNKNOWN_ERROR",
            message: `Failed to finalize DKG session: ${error instanceof Error ? error.message : 'Unknown error'}`,
            error
        }));
    }
}
