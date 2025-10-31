import { Result, err, ok } from "../../../../error";
import { DKGSession, PublishCommitmentError, PublishCommitmentParameters } from "../../port";

export function publishCommitment(
    sessions: Map<string, DKGSession>,
    session: DKGSession,
    params: PublishCommitmentParameters
): Promise<Result<DKGSession, PublishCommitmentError>> {
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
        if (currentSession.state !== 'INIT' && currentSession.state !== 'COMMITMENTS_PUBLISHED') {
            return Promise.resolve(err({
                code: "INVALID_STATE",
                message: `Cannot publish commitment in state ${currentSession.state}`
            }));
        }

        // Validate participant
        if (!currentSession.participants.includes(params.participantId)) {
            return Promise.resolve(err({
                code: "PARTICIPANT_NOT_FOUND",
                message: `Participant ${params.participantId} is not part of this session`
            }));
        }

        // Check if participant already published commitments
        if (currentSession.progress[params.participantId].hasPublishedCommitment) {
            return Promise.resolve(err({
                code: "DUPLICATE_COMMITMENT",
                message: `Participant ${params.participantId} has already published commitments`
            }));
        }

        // Validate commitment parameters
        if (!params.commitments || params.commitments.length === 0) {
            return Promise.resolve(err({
                code: "INVALID_COMMITMENTS",
                message: "Commitments array cannot be empty"
            }));
        }

        // For BLS scheme, commitments should be threshold + 1 in length
        if (params.commitments.length !== currentSession.threshold + 1) {
            return Promise.resolve(err({
                code: "INVALID_COMMITMENTS",
                message: `Expected ${currentSession.threshold + 1} commitments, got ${params.commitments.length}`
            }));
        }

        // Verify signature if provided (signature is now part of the commitment data)
        // In the client-side implementation, commitments are signed by the client
        // For now, we assume they are valid (signature verification will be done by clients)

        // Store commitments (generated client-side)
        currentSession.commitments[params.participantId] = params.commitments;
        currentSession.progress[params.participantId].hasPublishedCommitment = true;

        // Add to history
        currentSession.history!.push({
            timestamp: new Date().toISOString(),
            participantId: params.participantId,
            action: 'PUBLISH_COMMITMENT',
            details: { commitmentCount: params.commitments.length }
        });

        // Update session state if all participants have published commitments
        const allPublished = Object.values(currentSession.progress).every(p => p.hasPublishedCommitment);
        if (allPublished && currentSession.state === 'INIT') {
            currentSession.state = 'COMMITMENTS_PUBLISHED';
        }

        currentSession.updatedAt = new Date().toISOString();

        // Update stored session
        sessions.set(session.sessionId, currentSession);

        return Promise.resolve(ok(currentSession));
    } catch (error) {
        return Promise.resolve(err({
            code: "UNKNOWN_ERROR",
            message: `Failed to publish commitment: ${error instanceof Error ? error.message : 'Unknown error'}`,
            error
        }));
    }
}
