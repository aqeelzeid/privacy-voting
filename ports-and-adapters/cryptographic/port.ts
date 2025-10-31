import { Result } from '../../error';
import {
  PBKDF2PasswordDerivedKey,
  AESGCM256SymmetricKey,
  RSAOAEP2048AsymmetricKey,
  AESGCM256EncryptsAESGCM256Key,
  AESGCM256EncryptsRSAOAEP2048Key,
  AESGCM256EncryptsRSAPSS2048Key,
  RSAPSS2048AsymmetricKey,
  AESGCMSymmetricEncryptedData,
  HybridAESGCMEncryptedData,
  RSAOAEP2048EncryptsRSAPSS2048Key,
  RSAOAEP2048EncryptsAESGCM256Key,
  HashedStringContainer,
  EncodedStringContainer
} from '../../account/account';
import { PublicKeyContainer } from '../threshold-signature/port';

/**
 * Cryptographic operation error types
 */
export type CryptographicError =
  | { code: "KEY_GENERATION_FAILED"; message: string; cause?: unknown }
  | { code: "ENCRYPTION_FAILED"; message: string; cause?: unknown }
  | { code: "DECRYPTION_FAILED"; message: string; cause?: unknown }
  | { code: "INVALID_PASSWORD"; message: string; cause?: unknown }
  | { code: "INVALID_KEY_FORMAT"; message: string; cause?: unknown }
  | { code: "CRYPTO_API_ERROR"; message: string; cause?: unknown }
  | { code: "UNKNOWN"; message: string; cause?: unknown };

export interface CryptographicPort {
  /**
   * Generate a new PBKDF2 password-derived key
   * @param password - The password to derive the key from
   * @returns Result containing the generated password-derived key or error
   */
  generatePBKDF2PasswordDerivedKey(password: string): Promise<Result<PBKDF2PasswordDerivedKey, CryptographicError>>;

  /**
   * Generate a PBKDF2 password-derived key using specific parameters
   * @param password - The password to derive the key from
   * @param salt - The salt to use for key derivation
   * @param iterations - The number of iterations to use
   * @returns Result containing the generated password-derived key or error
   */
  generatePBKDF2PasswordDerivedKeyWithParameters(
    password: string,
    salt: string,
    iterations: number
  ): Promise<Result<PBKDF2PasswordDerivedKey, CryptographicError>>;

  /**
   * Get an AES-GCM-256 symmetric key from a PBKDF2 password-derived key
   * @param passwordDerivedKey - The password-derived key to use
   * @param password - The original password for verification
   * @returns Result containing the symmetric key or error
   */
  getAESGCM256SymmetricKeyFromPBKDF2PasswordDerivedKey(
    passwordDerivedKey: PBKDF2PasswordDerivedKey,
    password: string
  ): Promise<Result<AESGCM256SymmetricKey, CryptographicError>>;

  /**
   * Generate a new AES-GCM-256 symmetric key
   * @returns Result containing the generated symmetric key or error
   */
  generateAESGCM256KeyPair(): Promise<Result<AESGCM256SymmetricKey, CryptographicError>>;

  /**
   * Encrypt a PBKDF2 password-derived key with an AES-GCM-256 symmetric key
   * @param passwordDerivedKey - The password-derived key to encrypt
   * @param symmetricKey - The symmetric key to encrypt with
   * @returns Result containing the encrypted key container or error
   */
  encryptPBKDF2PasswordDerivedKeyWithAESGCM256(
    passwordDerivedKey: PBKDF2PasswordDerivedKey,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256EncryptsAESGCM256Key, CryptographicError>>;

  /**
   * Encrypt an AES-GCM-256 symmetric key with another AES-GCM-256 symmetric key
   * @param symmetricKeyToEncrypt - The symmetric key to encrypt
   * @param encryptionKey - The symmetric key to encrypt with
   * @returns Result containing the encrypted key container or error
   */
  encryptAESGCM256SymmetricKeyWithAESGCM256(
    symmetricKeyToEncrypt: AESGCM256SymmetricKey,
    encryptionKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256EncryptsAESGCM256Key, CryptographicError>>;

  /**
   * Generate a new RSA-2048 OAEP key pair
   * @returns Result containing the generated key pair or error
   */
  generateRSA2048OAEPKeyPair(): Promise<Result<RSAOAEP2048AsymmetricKey, CryptographicError>>;

  /**
   * Encrypt an RSA-2048 OAEP key pair with an AES-GCM-256 symmetric key
   * @param rsa2048OaepKeyPair - The RSA key pair to encrypt
   * @param symmetricKey - The symmetric key to encrypt with
   * @returns Result containing the encrypted key container or error
   */
  encryptRSA2048OAEPKeyPairWithAESGCM256(
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256EncryptsRSAOAEP2048Key, CryptographicError>>;

  /**
   * Encrypt arbitrary data with an AES-GCM-256 symmetric key
   * @param data - The data to encrypt as a Uint8Array
   * @param symmetricKey - The symmetric key to encrypt with
   * @returns Result containing the encrypted data container or error
   */
  encryptDataWithAESGCM256(
    data: Uint8Array,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<{
    encryptedData: string;
    iv: string;
    salt: string;
    tag: string;
    algorithm: string;
    version: string;
  }, CryptographicError>>;

  /**
   * Decrypt arbitrary data with an AES-GCM-256 symmetric key
   * @param encryptedData - The encrypted data container
   * @param symmetricKey - The symmetric key to decrypt with
   * @returns Result containing the decrypted data as Uint8Array or error
   */
  decryptDataWithAESGCM256(
    encryptedData: {
      encryptedData: string;
      iv: string;
      salt: string;
      tag: string;
      algorithm: string;
      version: string;
    },
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<Uint8Array, CryptographicError>>;

  /**
   * Encrypt arbitrary data using hybrid encryption (RSA-OAEP-2048 + AES-GCM-256)
   * This method combines asymmetric and symmetric encryption for optimal security and performance
   * @param dataBase64 - The data to encrypt as a Base64-encoded string
   * @param rsa2048OaepKeyPair - The RSA-OAEP-2048 key pair to encrypt the AES key with
   * @returns Result containing the hybrid encrypted data container or error
   */
  encryptDataWithHybridAESGCM256(
    dataBase64: string,
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<HybridAESGCMEncryptedData, CryptographicError>>;

  /**
   * Decrypt data encrypted with hybrid encryption (RSA-OAEP-2048 + AES-GCM-256)
   * @param encryptedData - The hybrid encrypted data container
   * @param rsa2048OaepKeyPair - The RSA-OAEP-2048 key pair to decrypt with
   * @returns Result containing the decrypted data as Base64-encoded string or error
   */
  decryptDataWithHybridAESGCM256(
    encryptedData: HybridAESGCMEncryptedData,
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<string, CryptographicError>>;

  /**
   * Encrypt wallet data using AES-GCM-256 and return standardized encrypted data container
   * @param walletData - The wallet data to encrypt as JSON string
   * @param symmetricKey - The symmetric key to encrypt with
   * @returns Result containing the AES-GCM encrypted data container or error
   */
  encryptWalletDataWithAESGCM256(
    walletData: string,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCMSymmetricEncryptedData, CryptographicError>>;

  /**
   * Decrypt wallet data from AES-GCM-256 encrypted data container
   * @param encryptedData - The AES-GCM encrypted data container
   * @param symmetricKey - The symmetric key to decrypt with
   * @returns Result containing the decrypted wallet data as string or error
   */
  decryptWalletDataWithAESGCM256(
    encryptedData: AESGCMSymmetricEncryptedData,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<string, CryptographicError>>;

  /**
   * Decrypt an AES-GCM-256 symmetric key with another AES-GCM-256 symmetric key
   * @param encryptedKey - The encrypted symmetric key container
   * @param symmetricKey - The symmetric key to decrypt with
   * @returns Result containing the decrypted symmetric key or error
   */
  decryptAESGCM256SymmetricKeyWithAESGCM256(
    encryptedKey: AESGCM256EncryptsAESGCM256Key,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256SymmetricKey, CryptographicError>>;

  /**
   * Decrypt an RSA-2048 OAEP key pair with an AES-GCM-256 symmetric key
   * @param encryptedKeyPair - The encrypted RSA key pair container
   * @param symmetricKey - The symmetric key to decrypt with
   * @returns Result containing the decrypted RSA key pair or error
   */
  decryptRSA2048OAEPKeyPairWithAESGCM256(
    encryptedKeyPair: AESGCM256EncryptsRSAOAEP2048Key,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<RSAOAEP2048AsymmetricKey, CryptographicError>>;

  /**
   * Verify a decrypted key pair by generating a signature and matching against public key
   * @param decryptedKeyPair - The decrypted RSA key pair
   * @param publicKey - The public key to verify against
   * @returns Result containing verification success or error
   */
  verifyDecryptedKeyPair(
    decryptedKeyPair: RSAOAEP2048AsymmetricKey,
    publicKey: { format: string; key: string }
  ): Promise<Result<boolean, CryptographicError>>;

  /**
   * Generate a new UUID
   * @returns Result containing the generated UUID or error
   */
  generateUUID(): Promise<Result<string, CryptographicError>>;

  /**
   * Generate a new OTP code
   * @param length - The length of the OTP code
   * @returns Result containing the generated OTP code or error
   */
  generateOTPCode(length: number): Promise<Result<number, CryptographicError>>;

  /**
   * Generate a new RSA-PSS-2048 key pair
   * @returns Result containing the generated key pair or error
   */
  generateRSA2048PSSKeyPair(): Promise<Result<RSAPSS2048AsymmetricKey, CryptographicError>>;

  /**
   * Encrypt an RSA-PSS-2048 key pair with an RSA-OAEP-2048 key pair
   * @param rsa2048PssKeyPair - The RSA-PSS key pair to encrypt
   * @param rsa2048OaepKeyPair - The RSA-OAEP key pair to encrypt with
   * @returns Result containing the encrypted key container or error
   */
  encryptRSA2048PSSKeyPairWithRSA2048OAEP(
    rsa2048PssKeyPair: RSAPSS2048AsymmetricKey,
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<RSAOAEP2048EncryptsRSAPSS2048Key, CryptographicError>>;

  /**
   * Decrypt an RSA-PSS-2048 key pair encrypted with an RSA-OAEP-2048 key pair (hybrid approach)
   * @param encryptedKeyPair - The encrypted RSA-PSS key pair container
   * @param rsa2048OaepKeyPair - The RSA-OAEP key pair to decrypt with
   * @returns Result containing the decrypted RSA-PSS key pair or error
   */
  decryptRSA2048PSSKeyPairWithRSA2048OAEP(
    encryptedKeyPair: RSAOAEP2048EncryptsRSAPSS2048Key,
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<RSAPSS2048AsymmetricKey, CryptographicError>>;

  /**
   * Encrypt an RSA-PSS-2048 key pair with an AES-GCM-256 symmetric key
   * @param rsa2048PssKeyPair - The RSA-PSS key pair to encrypt
   * @param symmetricKey - The AES-GCM-256 symmetric key to encrypt with
   * @returns Result containing the encrypted key container or error
   */
  encryptRSA2048PSSKeyPairWithAESGCM256(
    rsa2048PssKeyPair: RSAPSS2048AsymmetricKey,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256EncryptsRSAPSS2048Key, CryptographicError>>;

  /**
   * Decrypt an RSA-PSS-2048 key pair with an AES-GCM-256 symmetric key
   * @param encryptedKeyPair - The encrypted RSA-PSS key pair container
   * @param symmetricKey - The AES-GCM-256 symmetric key to decrypt with
   * @returns Result containing the decrypted RSA-PSS key pair or error
   */
  decryptRSA2048PSSKeyPairWithAESGCM256(
    encryptedKeyPair: AESGCM256EncryptsRSAPSS2048Key,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<RSAPSS2048AsymmetricKey, CryptographicError>>;

  /**
   * Encrypt an AES-GCM-256 symmetric key with an RSA-OAEP-2048 key pair
   * @param symmetricKey - The symmetric key to encrypt
   * @param rsa2048OaepKeyPair - The RSA-OAEP key pair to encrypt with
   * @returns Result containing the encrypted key container or error
   */
  encryptAESGCM256SymmetricKeyWithRSA2048OAEP(
    symmetricKey: AESGCM256SymmetricKey,
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<RSAOAEP2048EncryptsAESGCM256Key, CryptographicError>>;

  /**
   * Encrypt a Base64-encoded private key with an RSA-OAEP-2048 key pair (SEK)
   * This is used to encrypt PRE private keys to the creator's SEK for secure storage
   * @param privateKeyBase64 - The Base64-encoded private key to encrypt
   * @param sekKeyPair - The RSA-OAEP-2048 key pair (SEK) to encrypt with
   * @returns Result containing the encrypted private key or error
   */
  encryptBase64PrivateKeyWithRSA2048OAEP(
    privateKeyBase64: string,
    sekKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<{
    encryptedPrivateKeyBase64: string;
    algorithm: string;
    version: string;
  }, CryptographicError>>;

  // Legacy methods for threshold signature compatibility
  encryptWithRSAOAEP(
    data: Uint8Array,
    publicKey: PublicKeyContainer
  ): Promise<Result<EncodedStringContainer, unknown>>;

  decryptWithRSAOAEP(
    encryptedData: EncodedStringContainer,
    privateKey: AESGCM256EncryptsRSAOAEP2048Key,
    kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer }
  ): Promise<Result<Uint8Array, unknown>>;

  signWithRSAPSS(
    data: Uint8Array,
    privateKey: AESGCM256EncryptsRSAOAEP2048Key,
    kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer }
  ): Promise<Result<string, unknown>>;

  verifyRSAPSSSignature(
    data: Uint8Array,
    signature: string,
    publicKey: PublicKeyContainer
  ): Promise<Result<boolean, unknown>>;
}
