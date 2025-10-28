import { Result, ok, err } from '../error';
import {
  ACCOUNT_SCHEMA,
  PRIMARY_AUTHENTICATION_USER_SHARE_SCHEMA,
  KEY_SCHEMAS,
  ENCRYPTED_DATA_SCHEMAS,
  ENCRYPTED_KEY_SCHEMAS,
  HASH_SCHEMAS,
  ENCODED_STRING_SCHEMAS
} from './namespace';

// Cryptographic key schemas and types (without Zod)
export interface EncodedStringContainer {
  encoding: keyof typeof ENCODED_STRING_SCHEMAS;
  data: string;
}

export interface HashedStringContainer {
  algorithm: keyof typeof HASH_SCHEMAS;
  encoding: keyof typeof ENCODED_STRING_SCHEMAS;
  data: string;
}

// Core cryptographic types
export interface PasswordDerivedKey {
  format: 'pbkdf2-sha256';
  salt: EncodedStringContainer;
  iterations: number;
  key: EncodedStringContainer;
  fingerprint: HashedStringContainer;
}

export interface AESGCM256EncryptedData {
  format: 'aes-gcm-256';
  tag: EncodedStringContainer;
  iv: EncodedStringContainer;
  encrypted_data: EncodedStringContainer;
  fingerprint: HashedStringContainer;
}

export interface SymmetricEncryptsSymmetricKey {
  format: typeof ENCRYPTED_KEY_SCHEMAS.SYMMETRIC_ENCRYPTS_SYMMETRIC.AES_GCM_256_ENCRYPTS_AES_GCM_256;
  key: AESGCM256EncryptedData;
  fingerprint: HashedStringContainer;
}

export interface AESGCM256EncryptsRSAOAEP2048Key {
  format: typeof ENCRYPTED_KEY_SCHEMAS.SYMMETRIC_ENCRYPTS_ASYMMETRIC.AES_GCM_256_ENCRYPTS_RSA_OAEP_2048;
  fingerprint: HashedStringContainer;
  public_key: {
    format: typeof KEY_SCHEMAS.ENCODING.SPKI;
    key: EncodedStringContainer;
  };
  private_key: {
    format: typeof KEY_SCHEMAS.ENCODING.PKCS8;
    key: AESGCM256EncryptedData;
  };
}

export interface PrimaryAuthenticationUserShare {
  schema: typeof PRIMARY_AUTHENTICATION_USER_SHARE_SCHEMA;
  passwordDerivedKey: PasswordDerivedKey;
  keyEncryptionKey: SymmetricEncryptsSymmetricKey;
  secretEncryptionKey: AESGCM256EncryptsRSAOAEP2048Key;
  secretSigningKey: AESGCM256EncryptsRSAOAEP2048Key;
}

export interface AccountSchemaWithoutAccountId {
  usernameHash: HashedStringContainer;
  primaryAuthenticationUserShare: PrimaryAuthenticationUserShare;
  status: 'inactive' | 'active';
  schema: typeof ACCOUNT_SCHEMA;
  createdAt: string;
  updatedAt: string;
}

// Error types
export interface AccountGenerationError {
  code: string;
  message: string;
  error?: unknown;
}

// Cryptographic port interface (dependencies)
export interface CryptographicPort {
  sha256(data: string): Promise<Result<HashedStringContainer, unknown>>;
  generatePBKDF2PasswordDerivedKey(password: string): Promise<Result<PasswordDerivedKey, unknown>>;
  generateAESGCM256KeyPair(): Promise<Result<{ key: EncodedStringContainer; fingerprint: HashedStringContainer }, unknown>>;
  generateRSA2048OAEPKeyPair(): Promise<Result<AESGCM256EncryptsRSAOAEP2048Key, unknown>>;
  generateRSA2048PSSKeyPair(): Promise<Result<AESGCM256EncryptsRSAOAEP2048Key, unknown>>;
  getAESGCM256SymmetricKeyFromPBKDF2PasswordDerivedKey(
    pdk: PasswordDerivedKey,
    password: string
  ): Promise<Result<{ key: EncodedStringContainer; fingerprint: HashedStringContainer }, unknown>>;
  encryptAESGCM256SymmetricKeyWithAESGCM256(
    keyToEncrypt: { key: EncodedStringContainer; fingerprint: HashedStringContainer },
    encryptionKey: { key: EncodedStringContainer; fingerprint: HashedStringContainer }
  ): Promise<Result<SymmetricEncryptsSymmetricKey, unknown>>;
  encryptRSA2048OAEPKeyPairWithAESGCM256(
    keyPairToEncrypt: AESGCM256EncryptsRSAOAEP2048Key,
    encryptionKey: { key: EncodedStringContainer; fingerprint: HashedStringContainer }
  ): Promise<Result<AESGCM256EncryptsRSAOAEP2048Key, unknown>>;
  encryptRSA2048PSSKeyPairWithAESGCM256(
    keyPairToEncrypt: AESGCM256EncryptsRSAOAEP2048Key,
    encryptionKey: { key: EncodedStringContainer; fingerprint: HashedStringContainer }
  ): Promise<Result<AESGCM256EncryptsRSAOAEP2048Key, unknown>>;
}

export interface Dependencies {
  cryptographicPort: CryptographicPort;
  hashingPort: {
    sha256(data: string): Promise<Result<HashedStringContainer, unknown>>;
  };
}

// Account generation parameters
export interface GenerateAccountParameters {
  email: string;
  password: string;
}

/**
 * Generates a new user account with hierarchical key encryption.
 *
 * This function creates a complete cryptographic account following the wallet-style
 * key hierarchy: Password -> PDK -> KEK -> (SEK, SSK)
 *
 * @param dependencies - Cryptographic and hashing dependencies
 * @param parameters - Account generation parameters (email and password)
 * @returns Result containing the new account or an error
 */
export async function generateUserAccount(
  dependencies: Dependencies,
  parameters: GenerateAccountParameters
): Promise<Result<AccountSchemaWithoutAccountId, AccountGenerationError>> {
  try {
    // Generate username hash from email
    const usernameHashResult = await dependencies.hashingPort.sha256(parameters.email);

    if (!usernameHashResult.ok) {
      return err({
        code: "hashing_failed",
        message: "Failed to generate username hash",
        error: usernameHashResult.error
      });
    }

    // Generate password derived key using PBKDF2
    const passwordDerivedKeyResult = await dependencies.cryptographicPort.generatePBKDF2PasswordDerivedKey(parameters.password);
    if (!passwordDerivedKeyResult.ok) {
      return err({
        code: "password_derived_key_generation_failed",
        message: "Failed to generate password derived key",
        error: passwordDerivedKeyResult.error
      });
    }

    // console.log('🔑 Signup - Password Derived Key fingerprint:', passwordDerivedKeyResult.value.fingerprint);

    // Generate a random AES key as the Key Encryption Key (KEK)
    const keyEncryptionKeyGenerationResult = await dependencies.cryptographicPort.generateAESGCM256KeyPair();
    if (!keyEncryptionKeyGenerationResult.ok) {
      return err({
        code: "key_encryption_key_generation_failed",
        message: "Failed to generate key encryption key",
        error: keyEncryptionKeyGenerationResult.error
      });
    }

    // console.log('🔑 Signup - Key Encryption Key fingerprint:', keyEncryptionKeyGenerationResult.value.fingerprint);

    // Generate RSA-OAEP key pair for encryption
    const secretEncryptionKeyGenerationResult = await dependencies.cryptographicPort.generateRSA2048OAEPKeyPair();
    if (!secretEncryptionKeyGenerationResult.ok) {
      return err({
        code: "secret_encryption_key_generation_failed",
        message: "Failed to generate secret encryption key",
        error: secretEncryptionKeyGenerationResult.error
      });
    }

    // console.log('🔑 Signup - Secret Encryption Key fingerprint:', secretEncryptionKeyGenerationResult.value.fingerprint);

    // Generate RSA-PSS key pair for signing
    const secretSigningKeyGenerationResult = await dependencies.cryptographicPort.generateRSA2048PSSKeyPair();
    if (!secretSigningKeyGenerationResult.ok) {
      return err({
        code: "secret_signing_key_generation_failed",
        message: "Failed to generate secret signing key",
        error: secretSigningKeyGenerationResult.error
      });
    }

    // console.log('🔑 Signup - Secret Signing Key fingerprint:', secretSigningKeyGenerationResult.value.fingerprint);

    // Key hierarchy: PDK encrypts KEK, KEK encrypts SEK and SSK

    // Step 1: Derive AES key from PDK
    const derivedAESKeyResult = await dependencies.cryptographicPort.getAESGCM256SymmetricKeyFromPBKDF2PasswordDerivedKey(
      passwordDerivedKeyResult.value,
      parameters.password
    );
    if (!derivedAESKeyResult.ok) {
      return err({
        code: "aes_key_derivation_failed",
        message: "Failed to derive AES key from password",
        error: derivedAESKeyResult.error
      });
    }

    // console.log('🔑 Signup - Derived AES Key fingerprint:', derivedAESKeyResult.value.fingerprint);

    // Step 2: Use derived AES key to encrypt the KEK
    const keyEncryptionKeyResult = await dependencies.cryptographicPort.encryptAESGCM256SymmetricKeyWithAESGCM256(
      keyEncryptionKeyGenerationResult.value,
      derivedAESKeyResult.value
    );
    if (!keyEncryptionKeyResult.ok) {
      return err({
        code: "key_encryption_key_encryption_failed",
        message: "Failed to encrypt key encryption key with derived AES key",
        error: keyEncryptionKeyResult.error
      });
    }

    // console.log('🔑 Signup - Encrypted Key Encryption Key fingerprint:', keyEncryptionKeyResult.value.fingerprint);

    // Step 3: KEK encrypts SEK (RSA-OAEP for encryption)
    const secretEncryptionKeyResult = await dependencies.cryptographicPort.encryptRSA2048OAEPKeyPairWithAESGCM256(
      secretEncryptionKeyGenerationResult.value,
      keyEncryptionKeyGenerationResult.value
    );
    if (!secretEncryptionKeyResult.ok) {
      return err({
        code: "secret_encryption_key_encryption_failed",
        message: "Failed to encrypt secret encryption key with key encryption key",
        error: secretEncryptionKeyResult.error
      });
    }

    // console.log('🔑 Signup - Encrypted Secret Encryption Key fingerprint:', secretEncryptionKeyResult.value.fingerprint);

    // Step 4: KEK encrypts SSK (RSA-PSS for signing)
    const secretSigningKeyResult = await dependencies.cryptographicPort.encryptRSA2048PSSKeyPairWithAESGCM256(
      secretSigningKeyGenerationResult.value,
      keyEncryptionKeyGenerationResult.value
    );
    if (!secretSigningKeyResult.ok) {
      return err({
        code: "secret_signing_key_encryption_failed",
        message: "Failed to encrypt secret signing key with key encryption key",
        error: secretSigningKeyResult.error
      });
    }

    // console.log('🔑 Signup - Encrypted Secret Signing Key fingerprint:', secretSigningKeyResult.value.fingerprint);

    // Create the account object
    const account: AccountSchemaWithoutAccountId = {
      usernameHash: usernameHashResult.value,
      primaryAuthenticationUserShare: {
        schema: PRIMARY_AUTHENTICATION_USER_SHARE_SCHEMA as typeof PRIMARY_AUTHENTICATION_USER_SHARE_SCHEMA,
        passwordDerivedKey: passwordDerivedKeyResult.value,
        keyEncryptionKey: keyEncryptionKeyResult.value,
        secretEncryptionKey: secretEncryptionKeyResult.value,
        secretSigningKey: secretSigningKeyResult.value,
      },
      status: "inactive",
      schema: ACCOUNT_SCHEMA as typeof ACCOUNT_SCHEMA,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    return ok(account);

  } catch (error) {
    return err({
      code: "unexpected_error",
      message: "An unexpected error occurred during account generation",
      error
    });
  }
}
