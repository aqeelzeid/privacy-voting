import { Result } from '../../../error';

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

export interface VerifySharesError {
    code: "UNKNOWN_ERROR"
        | "DECRYPTION_FAILED"
        | "VERIFICATION_FAILED"
        | "KEY_DECRYPTION_FAILED"
        | "VALIDATION_ERROR";
    message: string;
    error?: unknown;
}








