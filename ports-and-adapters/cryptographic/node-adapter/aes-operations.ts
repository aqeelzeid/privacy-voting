import { randomBytes, createCipheriv, createDecipheriv, createHash, publicEncrypt, privateDecrypt, createPublicKey, createPrivateKey, constants } from 'crypto';
import { Result, ok, err } from '../../../error';
import { CryptographicError } from '../port';
import {
  AESGCM256SymmetricKey,
  PBKDF2PasswordDerivedKey,
  AESGCM256EncryptsAESGCM256Key,
  AESGCM256EncryptsRSAOAEP2048Key,
  AESGCM256EncryptsRSAPSS2048Key,
  RSAOAEP2048AsymmetricKey,
  RSAPSS2048AsymmetricKey,
  AESGCMSymmetricEncryptedData,
  HybridAESGCMEncryptedData,
} from '../../../account/account';
import {
  KEY_SCHEMAS,
  ENCRYPTED_KEY_SCHEMAS,
  ENCRYPTED_DATA_SCHEMAS,
} from '../../../account/namespace';
import { CryptoUtils } from './utils';

/**
 * AES encryption/decryption operations
 */
export class AESOperations {
  /**
   * Encrypt a PBKDF2 password-derived key with an AES-GCM-256 symmetric key
   */
  static async encryptPBKDF2PasswordDerivedKeyWithAESGCM256(
    passwordDerivedKey: PBKDF2PasswordDerivedKey,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256EncryptsAESGCM256Key, CryptographicError>> {
    try {
      const keyBuffer = CryptoUtils.decodeBase64(symmetricKey.key.data);
      const dataToEncrypt = CryptoUtils.decodeBase64(passwordDerivedKey.derived_key.data);

      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', keyBuffer, iv);
      const encrypted = Buffer.concat([cipher.update(dataToEncrypt), cipher.final()]);
      const tag = cipher.getAuthTag();

      return ok({
        format: ENCRYPTED_KEY_SCHEMAS.SYMMETRIC_ENCRYPTS_SYMMETRIC.AES_GCM_256_ENCRYPTS_AES_GCM_256,
        key: {
          format: ENCRYPTED_DATA_SCHEMAS.SYMMETRIC.AES_GCM_256,
          tag: CryptoUtils.createEncodedStringContainer(tag),
          iv: CryptoUtils.createEncodedStringContainer(iv),
          encrypted_data: CryptoUtils.createEncodedStringContainer(encrypted),
          fingerprint: symmetricKey.fingerprint
        },
        fingerprint: passwordDerivedKey.fingerprint
      });
    } catch (error) {
      return err({
        code: "ENCRYPTION_FAILED",
        message: "Failed to encrypt PBKDF2 password-derived key with AES-GCM-256",
        cause: error
      });
    }
  }

  /**
   * Encrypt an AES-GCM-256 symmetric key with another AES-GCM-256 symmetric key
   */
  static async encryptAESGCM256SymmetricKeyWithAESGCM256(
    symmetricKeyToEncrypt: AESGCM256SymmetricKey,
    encryptionKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256EncryptsAESGCM256Key, CryptographicError>> {
    try {
      const keyBuffer = CryptoUtils.decodeBase64(encryptionKey.key.data);
      const dataToEncrypt = CryptoUtils.decodeBase64(symmetricKeyToEncrypt.key.data);

      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', keyBuffer, iv);
      const encrypted = Buffer.concat([cipher.update(dataToEncrypt), cipher.final()]);
      const tag = cipher.getAuthTag();

      return ok({
        format: ENCRYPTED_KEY_SCHEMAS.SYMMETRIC_ENCRYPTS_SYMMETRIC.AES_GCM_256_ENCRYPTS_AES_GCM_256,
        key: {
          format: ENCRYPTED_DATA_SCHEMAS.SYMMETRIC.AES_GCM_256,
          tag: CryptoUtils.createEncodedStringContainer(tag),
          iv: CryptoUtils.createEncodedStringContainer(iv),
          encrypted_data: CryptoUtils.createEncodedStringContainer(encrypted),
          fingerprint: encryptionKey.fingerprint
        },
        fingerprint: symmetricKeyToEncrypt.fingerprint
      });
    } catch (error) {
      return err({
        code: "ENCRYPTION_FAILED",
        message: "Failed to encrypt AES-GCM-256 symmetric key with AES-GCM-256",
        cause: error
      });
    }
  }

  /**
   * Encrypt an RSA-2048 OAEP key pair with an AES-GCM-256 symmetric key
   */
  static async encryptRSA2048OAEPKeyPairWithAESGCM256(
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256EncryptsRSAOAEP2048Key, CryptographicError>> {
    try {
      const keyBuffer = CryptoUtils.decodeBase64(symmetricKey.key.data);
      const privateKeyData = CryptoUtils.decodeBase64(rsa2048OaepKeyPair.private_key.key.data);

      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', keyBuffer, iv);
      const encrypted = Buffer.concat([cipher.update(privateKeyData), cipher.final()]);
      const tag = cipher.getAuthTag();

      return ok({
        format: ENCRYPTED_KEY_SCHEMAS.SYMMETRIC_ENCRYPTS_ASYMMETRIC.AES_GCM_256_ENCRYPTS_RSA_OAEP_2048,
        fingerprint: rsa2048OaepKeyPair.fingerprint,
        public_key: rsa2048OaepKeyPair.public_key,
        private_key: {
          format: KEY_SCHEMAS.ENCODING.PKCS8,
          key: {
            format: ENCRYPTED_DATA_SCHEMAS.SYMMETRIC.AES_GCM_256,
            tag: CryptoUtils.createEncodedStringContainer(tag),
            iv: CryptoUtils.createEncodedStringContainer(iv),
            encrypted_data: CryptoUtils.createEncodedStringContainer(encrypted),
            fingerprint: symmetricKey.fingerprint
          }
        }
      });
    } catch (error) {
      return err({
        code: "ENCRYPTION_FAILED",
        message: "Failed to encrypt RSA-2048 OAEP key pair with AES-GCM-256",
        cause: error
      });
    }
  }

  /**
   * Encrypt arbitrary data with an AES-GCM-256 symmetric key
   */
  static async encryptDataWithAESGCM256(
    data: Uint8Array,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<{
    encryptedData: string;
    iv: string;
    salt: string;
    tag: string;
    algorithm: string;
    version: string;
  }, CryptographicError>> {
    try {
      const keyBuffer = CryptoUtils.decodeBase64(symmetricKey.key.data);
      const iv = randomBytes(12);
      const salt = randomBytes(16);

      const cipher = createCipheriv('aes-256-gcm', keyBuffer, iv);
      const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
      const tag = cipher.getAuthTag();

      return ok({
        encryptedData: CryptoUtils.encodeBase64(encrypted),
        iv: CryptoUtils.encodeBase64(iv),
        salt: CryptoUtils.encodeBase64(salt),
        tag: CryptoUtils.encodeBase64(tag),
        algorithm: "AES-GCM-256",
        version: "1.0.0",
      });
    } catch (error) {
      return err({
        code: "ENCRYPTION_FAILED",
        message: "Failed to encrypt data with AES-GCM-256",
        cause: error
      });
    }
  }

  /**
   * Decrypt arbitrary data with an AES-GCM-256 symmetric key
   */
  static async decryptDataWithAESGCM256(
    encryptedData: {
      encryptedData: string;
      iv: string;
      salt: string;
      tag: string;
      algorithm: string;
      version: string;
    },
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<Uint8Array, CryptographicError>> {
    try {
      const keyBuffer = CryptoUtils.decodeBase64(symmetricKey.key.data);
      const encryptedBuffer = CryptoUtils.decodeBase64(encryptedData.encryptedData);
      const iv = CryptoUtils.decodeBase64(encryptedData.iv);
      const tag = CryptoUtils.decodeBase64(encryptedData.tag);

      const decipher = createDecipheriv('aes-256-gcm', keyBuffer, iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);

      return ok(decrypted);
    } catch (error) {
      return err({
        code: "DECRYPTION_FAILED",
        message: "Failed to decrypt data with AES-GCM-256",
        cause: error
      });
    }
  }

  /**
   * Encrypt data using hybrid encryption (RSA-OAEP-2048 + AES-GCM-256)
   */
  static async encryptDataWithHybridAESGCM256(
    dataBase64: string,
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<HybridAESGCMEncryptedData, CryptographicError>> {
    try {
      // Generate AES key for data encryption
      const aesKey = randomBytes(32);
      const data = CryptoUtils.decodeBase64(dataBase64);

      // Encrypt data with AES-GCM
      const dataIv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', aesKey, dataIv);
      const encryptedData = Buffer.concat([cipher.update(data), cipher.final()]);
      const dataTag = cipher.getAuthTag();

      // Encrypt AES key with RSA-OAEP using DER-encoded key
      const publicKeyDer = Buffer.from(CryptoUtils.decodeBase64(rsa2048OaepKeyPair.public_key.key.data));
      const publicKey = createPublicKey({
        key: publicKeyDer,
        format: 'der',
        type: 'spki'
      });
      const encryptedAesKey = publicEncrypt({
        key: publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      }, aesKey);

      return ok({
        format: ENCRYPTED_DATA_SCHEMAS.HYBRID.AES_GCM_256,
        asymmetric_key: {
          schema: ENCRYPTED_DATA_SCHEMAS.ASYMMETRIC.RSA_OAEP_2048,
          fingerprint: rsa2048OaepKeyPair.fingerprint
        },
        encrypted_key: {
          format: ENCRYPTED_DATA_SCHEMAS.SYMMETRIC.AES_GCM_256,
          tag: CryptoUtils.createEncodedStringContainer(new Uint8Array(0)), // Not used in this implementation
          iv: CryptoUtils.createEncodedStringContainer(new Uint8Array(0)), // Not used in this implementation
          encrypted_data: CryptoUtils.createEncodedStringContainer(encryptedAesKey)
        },
        encrypted_data: {
          format: ENCRYPTED_DATA_SCHEMAS.SYMMETRIC.AES_GCM_256,
          tag: CryptoUtils.createEncodedStringContainer(dataTag),
          iv: CryptoUtils.createEncodedStringContainer(dataIv),
          encrypted_data: CryptoUtils.createEncodedStringContainer(encryptedData)
        }
      });
    } catch (error) {
      return err({
        code: "ENCRYPTION_FAILED",
        message: "Failed to encrypt data with hybrid AES-GCM-256",
        cause: error
      });
    }
  }

  /**
   * Decrypt data encrypted with hybrid encryption (RSA-OAEP-2048 + AES-GCM-256)
   */
  static async decryptDataWithHybridAESGCM256(
    encryptedData: HybridAESGCMEncryptedData,
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<string, CryptographicError>> {
    try {
      // Decrypt AES key with RSA-OAEP using DER-encoded key
      const privateKeyDer = Buffer.from(CryptoUtils.decodeBase64(rsa2048OaepKeyPair.private_key.key.data));
      const privateKey = createPrivateKey({
        key: privateKeyDer,
        format: 'der',
        type: 'pkcs8'
      });
      const encryptedAesKey = CryptoUtils.decodeBase64(encryptedData.encrypted_key.encrypted_data.data);
      const aesKey = privateDecrypt({
        key: privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      }, encryptedAesKey);

      // Decrypt data with AES-GCM
      const encryptedDataBuffer = CryptoUtils.decodeBase64(encryptedData.encrypted_data.encrypted_data.data);
      const iv = CryptoUtils.decodeBase64(encryptedData.encrypted_data.iv.data);
      const tag = CryptoUtils.decodeBase64(encryptedData.encrypted_data.tag.data);

      const decipher = createDecipheriv('aes-256-gcm', aesKey, iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([decipher.update(encryptedDataBuffer), decipher.final()]);
      const decryptedBase64 = CryptoUtils.encodeBase64(decrypted);

      return ok(decryptedBase64);
    } catch (error) {
      return err({
        code: "DECRYPTION_FAILED",
        message: "Failed to decrypt data with hybrid AES-GCM-256",
        cause: error
      });
    }
  }

  /**
   * Encrypt wallet data using AES-GCM-256 and return standardized encrypted data container
   */
  static async encryptWalletDataWithAESGCM256(
    walletData: string,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCMSymmetricEncryptedData, CryptographicError>> {
    try {
      const keyBuffer = CryptoUtils.decodeBase64(symmetricKey.key.data);
      const data = new TextEncoder().encode(walletData);

      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', keyBuffer, iv);
      const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
      const tag = cipher.getAuthTag();

      const fingerprintHash = await createHash('sha256').update(keyBuffer).digest();
      const fingerprintBase64 = CryptoUtils.encodeBase64(fingerprintHash);

      return ok({
        format: ENCRYPTED_DATA_SCHEMAS.SYMMETRIC.AES_GCM_256,
        tag: CryptoUtils.createEncodedStringContainer(tag),
        iv: CryptoUtils.createEncodedStringContainer(iv),
        encrypted_data: CryptoUtils.createEncodedStringContainer(encrypted),
        fingerprint: CryptoUtils.createHashedStringContainer('SHA256', fingerprintBase64)
      });
    } catch (error) {
      return err({
        code: "ENCRYPTION_FAILED",
        message: "Failed to encrypt wallet data with AES-GCM-256",
        cause: error
      });
    }
  }

  /**
   * Decrypt wallet data from AES-GCM-256 encrypted data container
   */
  static async decryptWalletDataWithAESGCM256(
    encryptedData: AESGCMSymmetricEncryptedData,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<string, CryptographicError>> {
    try {
      const keyBuffer = CryptoUtils.decodeBase64(symmetricKey.key.data);
      const encryptedBuffer = CryptoUtils.decodeBase64(encryptedData.encrypted_data.data);
      const iv = CryptoUtils.decodeBase64(encryptedData.iv.data);
      const tag = CryptoUtils.decodeBase64(encryptedData.tag.data);

      const decipher = createDecipheriv('aes-256-gcm', keyBuffer, iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
      const decryptedString = new TextDecoder().decode(decrypted);

      return ok(decryptedString);
    } catch (error) {
      return err({
        code: "DECRYPTION_FAILED",
        message: "Failed to decrypt wallet data with AES-GCM-256",
        cause: error
      });
    }
  }

  /**
   * Decrypt an AES-GCM-256 symmetric key with another AES-GCM-256 symmetric key
   */
  static async decryptAESGCM256SymmetricKeyWithAESGCM256(
    encryptedKey: AESGCM256EncryptsAESGCM256Key,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256SymmetricKey, CryptographicError>> {
    try {
      const keyBuffer = CryptoUtils.decodeBase64(symmetricKey.key.data);
      const encryptedBuffer = CryptoUtils.decodeBase64(encryptedKey.key.encrypted_data.data);
      const iv = CryptoUtils.decodeBase64(encryptedKey.key.iv.data);
      const tag = CryptoUtils.decodeBase64(encryptedKey.key.tag.data);

      const decipher = createDecipheriv('aes-256-gcm', keyBuffer, iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);

      const fingerprintHash = await createHash('sha256').update(decrypted).digest();
      const fingerprintBase64 = CryptoUtils.encodeBase64(fingerprintHash);

      return ok({
        format: KEY_SCHEMAS.SYMMETRIC.AES_GCM_256,
        key: CryptoUtils.createEncodedStringContainer(decrypted),
        fingerprint: CryptoUtils.createHashedStringContainer('SHA256', fingerprintBase64)
      });
    } catch (error) {
      return err({
        code: "DECRYPTION_FAILED",
        message: "Failed to decrypt AES-GCM-256 symmetric key",
        cause: error
      });
    }
  }

  /**
   * Decrypt an RSA-2048 OAEP key pair with an AES-GCM-256 symmetric key
   */
  static async decryptRSA2048OAEPKeyPairWithAESGCM256(
    encryptedKeyPair: AESGCM256EncryptsRSAOAEP2048Key,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<RSAOAEP2048AsymmetricKey, CryptographicError>> {
    try {
      const keyBuffer = CryptoUtils.decodeBase64(symmetricKey.key.data);
      const encryptedBuffer = CryptoUtils.decodeBase64(encryptedKeyPair.private_key.key.encrypted_data.data);
      const iv = CryptoUtils.decodeBase64(encryptedKeyPair.private_key.key.iv.data);
      const tag = CryptoUtils.decodeBase64(encryptedKeyPair.private_key.key.tag.data);

      const decipher = createDecipheriv('aes-256-gcm', keyBuffer, iv);
      decipher.setAuthTag(tag);
      const decryptedPrivateKey = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
      const privateKeyBase64 = CryptoUtils.encodeBase64(decryptedPrivateKey);

      return ok({
        format: KEY_SCHEMAS.ASYMMETRIC.RSA_OAEP_2048,
        fingerprint: encryptedKeyPair.fingerprint,
        public_key: encryptedKeyPair.public_key,
        private_key: {
          format: KEY_SCHEMAS.ENCODING.PKCS8,
          key: CryptoUtils.createEncodedStringContainer(new TextEncoder().encode(privateKeyBase64))
        }
      });
    } catch (error) {
      return err({
        code: "DECRYPTION_FAILED",
        message: "Failed to decrypt RSA-2048 OAEP key pair with AES-GCM-256",
        cause: error
      });
    }
  }

  /**
   * Verify a decrypted key pair by generating a signature and matching against public key
   */
  static async verifyDecryptedKeyPair(
    decryptedKeyPair: RSAOAEP2048AsymmetricKey,
    publicKey: { format: string; key: string }
  ): Promise<Result<boolean, CryptographicError>> {
    try {
      const testData = randomBytes(32);
      const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${CryptoUtils.decodeBase64(publicKey.key)}\n-----END PUBLIC KEY-----`;
      const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${CryptoUtils.decodeBase64(decryptedKeyPair.private_key.key.data)}\n-----END PRIVATE KEY-----`;

      const encrypted = publicEncrypt(publicKeyPem, testData);
      const decrypted = privateDecrypt(privateKeyPem, encrypted);

      return ok(testData.equals(decrypted));
    } catch (error) {
      return err({
        code: "CRYPTO_API_ERROR",
        message: "Failed to verify decrypted key pair",
        cause: error
      });
    }
  }
}
