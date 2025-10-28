/**
 * @module @abiogenesys/identity/entities.refactor/namespace
 * @description Namespace Management for Standardized Cryptographic Containers
 */

/**
 * Base namespace configuration
 */
export const ABIOGENESYS_NAMESPACE = {
  BASE: "https://abiogenesys.io",
  CONTAINERS: "/containers",
  KEYS: "/keys",
  VERSION: "/1.0.0"
} as const;

export const SIGNUP_SESSION_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/signup/session/1.0.0` as const;
export const ACCOUNT_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/account/1.0.0` as const;
export const PRIMARY_AUTHENTICATION_USER_SHARE_SCHEMA = "https://abiogenesys.io/identity/account/primary-authentication/user-share/1.0.0" as const;
export const PRIMARY_AUTHENTICATION_SYSTEM_SHARE_SCHEMA = "https://abiogenesys.io/identity/account/primary-authentication/system-share/1.0.0" as const;
export const SECONDARY_AUTHENTICATION_TOTP_SCHEMA = "https://abiogenesys.io/identity/account/secondary-authentication/totp/1.0.0" as const;
export const PROFILE_INFORMATION_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/account/profile-information/1.0.0` as const;

// Group-related schemas
export const GROUP_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/group/1.0.0` as const;
export const GROUP_PROFILE_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/group/profile/1.0.0` as const;
export const GROUP_MEMBER_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/group/member/1.0.0` as const;
export const GROUP_MEMBERS_SECTION_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/group/members/1.0.0` as const;
export const GROUP_COMMITTEE_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/group/committee/1.0.0` as const;
export const GROUP_PRIVACY_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/group/privacy/1.0.0` as const;
export const GROUP_PRIVACY_CUSTODIAN_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/group/privacy/custodian/1.0.0` as const;
export const GROUP_PRIVACY_MEMBER_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/group/privacy/member/1.0.0` as const;

// Committee types
export const SOLO_EXECUTIVE_COMMITTEE = `${ABIOGENESYS_NAMESPACE.BASE}/identity/group/committee/solo-executive/1.0.0` as const;
export const TOKEN_WEIGHTED_COMMITTEE = `${ABIOGENESYS_NAMESPACE.BASE}/identity/group/committee/token-weighted/1.0.0` as const;

// Provenance chain schemas
export const GROUP_PROVENANCE_RECORD_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/group/provenance/record/1.0.0` as const;
export const SOLO_EXECUTOR_COMMITTEE_HISTORY_RECORD_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/group/provenance/solo-executor-committee/1.0.0` as const;
export const TOKEN_WEIGHTED_COMMITTEE_HISTORY_RECORD_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/group/provenance/token-weighted-committee/1.0.0` as const;

// Voting center schemas
export const VOTING_CENTER_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/voting-center/1.0.0` as const;
export const VOTING_PROPOSAL_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/voting-center/proposal/1.0.0` as const;
export const VOTING_SESSION_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/voting-center/session/1.0.0` as const;
export const VOTING_BALLOT_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/voting-center/ballot/1.0.0` as const;
export const VOTING_RESULT_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/voting-center/result/1.0.0` as const;

// Action Queue schemas
export const ACTION_QUEUE_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/action-queue/1.0.0` as const;
export const ACTION_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/action-queue/action/1.0.0` as const;
export const ACTION_DISPLAY_DATA_SCHEMA = `${ABIOGENESYS_NAMESPACE.BASE}/identity/action-queue/action/display-data/1.0.0` as const;


/**
 * Encoded String Container Schema URLs
 */
export const ENCODED_STRING_SCHEMAS = {
  // Base64 variants
  BASE64_STANDARD_PADDED: "http://abiogenesys.io/containers/binary-encoded-string/base64?variant=standard&padding=required&linebreaks=none",
  BASE64_STANDARD_UNPADDED: "http://abiogenesys.io/containers/binary-encoded-string/base64?variant=standard&padding=none&linebreaks=none",
  BASE64URL_UNPADDED: "http://abiogenesys.io/containers/binary-encoded-string/base64?variant=url&padding=none&linebreaks=none",
  BASE64URL_PADDED: "http://abiogenesys.io/containers/binary-encoded-string/base64?variant=url&padding=required&linebreaks=none",
  BASE64_MIME: "http://abiogenesys.io/containers/binary-encoded-string/base64?variant=standard&padding=required&linebreaks=76",

  // Base58 variants
  BASE58_BTC: "http://abiogenesys.io/containers/binary-encoded-string/base58?variant=btc",
  BASE58_FLICKR: "http://abiogenesys.io/containers/binary-encoded-string/base58?variant=flickr",

  // Hex variants
  HEX_LOWERCASE: "http://abiogenesys.io/containers/binary-encoded-string/hex?case=lower",
  HEX_UPPERCASE: "http://abiogenesys.io/containers/binary-encoded-string/hex?case=upper",

  // Multibase variants
  MULTIBASE: "http://abiogenesys.io/containers/binary-encoded-string/multibase",
  MULTIBASE_BASE64URL: "http://abiogenesys.io/containers/binary-encoded-string/multibase?variant=base64url",
  MULTIBASE_BASE58BTC: "http://abiogenesys.io/containers/binary-encoded-string/multibase?variant=base58btc"
} as const;

/**
 * Hash Container Schema URLs
 */
export const HASH_SCHEMAS = {
  SHA256: "https://abiogenesys.io/containers/hashes/sha256",
  SHA384: "https://abiogenesys.io/containers/hashes/sha384",
  SHA512: "https://abiogenesys.io/containers/hashes/sha512",
  BLAKE2B: "https://abiogenesys.io/containers/hashes/blake2b",
  BLAKE3: "https://abiogenesys.io/containers/hashes/blake3"
} as const;

/**
 * Key Container Schema URLs
 */
export const KEY_SCHEMAS = {
  // Symmetric keys
  SYMMETRIC: {
    AES_GCM_256: "https://abiogenesys.io/keys/symmetric/aes-gcm-256",
    AES_GCM_128: "https://abiogenesys.io/keys/symmetric/aes-gcm-128",
    CHACHA20_POLY1305: "https://abiogenesys.io/keys/symmetric/chacha20-poly1305"
  },

  // Asymmetric keys
  ASYMMETRIC: {
    RSA_PSS_2048: "https://abiogenesys.io/keys/asymmetric/rsa-pss-2048",
    RSA_PSS_4096: "https://abiogenesys.io/keys/asymmetric/rsa-pss-4096",
    RSA_OAEP_2048: "https://abiogenesys.io/keys/asymmetric/rsa-oaep-2048",
    RSA_OAEP_4096: "https://abiogenesys.io/keys/asymmetric/rsa-oaep-4096",
    ED25519: "https://abiogenesys.io/keys/asymmetric/ed25519",
    SECP256K1: "https://abiogenesys.io/keys/asymmetric/secp256k1"
  },

  // Proxy Re-Encryption keys
  PROXY_RE_ENCRYPTION: {
    RSA_OAEP_2048_TO_RSA_OAEP_2048: "https://abiogenesys.io/keys/proxy-re-encryption/rsa-oaep-2048-to-rsa-oaep-2048",
    RSA_OAEP_2048_TO_AES_GCM_256: "https://abiogenesys.io/keys/proxy-re-encryption/rsa-oaep-2048-to-aes-gcm-256"
  },

  // Key encoding formats
  ENCODING: {
    SPKI: "https://abiogenesys.io/keys/encoding/spki",
    PKCS8: "https://abiogenesys.io/keys/encoding/pkcs8",
    JWK: "https://abiogenesys.io/keys/encoding/jwk",
    RAW: "https://abiogenesys.io/keys/encoding/raw"
  },

  // Password derived keys
  PASSWORD_DERIVED: {
    PBKDF2: "https://abiogenesys.io/containers/keys/pbkdf2",
    ARGON2ID: "https://abiogenesys.io/containers/keys/argon2id",
    SCRYPT: "https://abiogenesys.io/containers/keys/scrypt"
  }
} as const;

/**
 * Encrypted Data Container Schema URLs
 */
export const ENCRYPTED_DATA_SCHEMAS = {
  // Symmetric encryption
  SYMMETRIC: {
    AES_GCM_256: "https://abiogenesys.io/containers/encrypted/symmetric/aes-gcm-256",
    AES_GCM_128: "https://abiogenesys.io/containers/encrypted/symmetric/aes-gcm-128",
    CHACHA20_POLY1305: "https://abiogenesys.io/containers/encrypted/symmetric/chacha20-poly1305"
  },

  // Asymmetric encryption
  ASYMMETRIC: {
    RSA_OAEP_2048: "https://abiogenesys.io/containers/encrypted/asymmetric/rsa-oaep-2048",
    RSA_OAEP_4096: "https://abiogenesys.io/containers/encrypted/asymmetric/rsa-oaep-4096"
  },

  // Hybrid encryption
  HYBRID: {
    AES_GCM_256: "https://abiogenesys.io/containers/encrypted/hybrid/aes-gcm-256",
    CHACHA20_POLY1305: "https://abiogenesys.io/containers/encrypted/hybrid/chacha20-poly1305"
  }
} as const;

/**
 * Encrypted Key Container Schema URLs
 */
export const ENCRYPTED_KEY_SCHEMAS = {
  // Asymmetric encrypts symmetric
  ASYMMETRIC_ENCRYPTS_SYMMETRIC: {
    RSA_OAEP_2048_ENCRYPTS_AES_GCM_256: "https://abiogenesys.io/containers/encrypted/key/asymmetric-encrypts-symmetric/rsa-oaep-2048-encrypts-aes-gcm-256",
    RSA_OAEP_4096_ENCRYPTS_AES_GCM_256: "https://abiogenesys.io/containers/encrypted/key/asymmetric-encrypts-symmetric/rsa-oaep-4096-encrypts-aes-gcm-256"
  },

  // Symmetric encrypts asymmetric
  SYMMETRIC_ENCRYPTS_ASYMMETRIC: {
    AES_GCM_256_ENCRYPTS_RSA_OAEP_2048: "https://abiogenesys.io/containers/encrypted/key/symmetric-encrypts-asymmetric/aes-gcm-256-encrypts-rsa-oaep-2048",
    AES_GCM_256_ENCRYPTS_RSA_PSS_2048: "https://abiogenesys.io/containers/encrypted/key/symmetric-encrypts-asymmetric/aes-gcm-256-encrypts-rsa-pss-2048"
  },

  // Symmetric encrypts symmetric
  SYMMETRIC_ENCRYPTS_SYMMETRIC: {
    AES_GCM_256_ENCRYPTS_AES_GCM_256: "https://abiogenesys.io/containers/encrypted/key/symmetric-encrypts-symmetric/aes-gcm-256-encrypts-aes-gcm-256"
  },

  // Asymmetric encrypts asymmetric
  ASYMMETRIC_ENCRYPTS_ASYMMETRIC: {
    RSA_OAEP_2048_ENCRYPTS_RSA_PSS_2048: "https://abiogenesys.io/containers/encrypted/key/asymmetric-encrypts-asymmetric/rsa-oaep-2048-encrypts-rsa-pss-2048"
  },

  // PRE encrypts symmetric (NEW)
  PRE_ENCRYPTS_SYMMETRIC: {
    UMBRAL_PRE_ENCRYPTS_AES_GCM_256: "https://abiogenesys.io/containers/encrypted/key/pre-encrypts-symmetric/umbral-pre-encrypts-aes-gcm-256"
  }
} as const;

/**
 * Application Entity Schema URLs
 */
export const APPLICATION_SCHEMAS = {
  // Group governance schemas
  GROUP: {
    BASE: GROUP_SCHEMA,
    PROFILE: GROUP_PROFILE_SCHEMA,
    MEMBER: GROUP_MEMBER_SCHEMA,
    COMMITTEE: GROUP_COMMITTEE_SCHEMA,
    PRIVACY: GROUP_PRIVACY_SCHEMA,
    PROVENANCE: {
      RECORD: GROUP_PROVENANCE_RECORD_SCHEMA,
      SOLO_EXECUTOR: SOLO_EXECUTOR_COMMITTEE_HISTORY_RECORD_SCHEMA,
      TOKEN_WEIGHTED: TOKEN_WEIGHTED_COMMITTEE_HISTORY_RECORD_SCHEMA,
    }
  },

  // Committee schemas
  COMMITTEE: {
    SOLO_EXECUTIVE: SOLO_EXECUTIVE_COMMITTEE,
    TOKEN_WEIGHTED: TOKEN_WEIGHTED_COMMITTEE,
  },

  // Voting center schemas
  VOTING_CENTER: {
    BASE: VOTING_CENTER_SCHEMA,
    PROPOSAL: VOTING_PROPOSAL_SCHEMA,
    SESSION: VOTING_SESSION_SCHEMA,
    BALLOT: VOTING_BALLOT_SCHEMA,
    RESULT: VOTING_RESULT_SCHEMA,
  },

  // Action Queue schemas
  ACTION_QUEUE: {
    BASE: ACTION_QUEUE_SCHEMA,
    ACTION: ACTION_SCHEMA,
    DISPLAY_DATA: ACTION_DISPLAY_DATA_SCHEMA,
  }
} as const;
