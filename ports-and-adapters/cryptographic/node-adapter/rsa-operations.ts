import { randomBytes, createCipheriv, createDecipheriv, publicEncrypt, privateDecrypt, createSign, createVerify, constants } from 'crypto';
import { Result, ok, err } from '../../../error';
import { CryptographicError } from '../port';
import {
  AESGCM256SymmetricKey,
  RSAPSS2048AsymmetricKey,
  RSAOAEP2048EncryptsRSAPSS2048Key,
  RSAOAEP2048EncryptsAESGCM256Key,
  EncodedStringContainer,
  HashedStringContainer,
  AESGCM256EncryptsRSAOAEP2048Key
} from '../../../account/account';
import {
  ENCRYPTED_KEY_SCHEMAS,
  ENCRYPTED_DATA_SCHEMAS,
  KEY_SCHEMAS,
} from '../../../account/namespace';
import { PublicKeyContainer } from '../../threshold-signature/port';
import { CryptoUtils } from './utils';

/**
 * RSA encryption/decryption operations
 */
export class RSAOperations {
  /**
   * Encrypt an RSA-PSS-2048 key pair with an AES-GCM-256 symmetric key
   */
  static async encryptRSA2048PSSKeyPairWithAESGCM256(
    rsa2048PssKeyPair: RSAPSS2048AsymmetricKey,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<any, CryptographicError>> {
    try {
      const keyBuffer = CryptoUtils.decodeBase64(symmetricKey.key.data);
      const privateKeyData = CryptoUtils.decodeBase64(rsa2048PssKeyPair.private_key.key.data);

      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', keyBuffer, iv);
      const encrypted = Buffer.concat([cipher.update(privateKeyData), cipher.final()]);
      const tag = cipher.getAuthTag();

      return ok({
        format: ENCRYPTED_KEY_SCHEMAS.SYMMETRIC_ENCRYPTS_ASYMMETRIC.AES_GCM_256_ENCRYPTS_RSA_PSS_2048,
        fingerprint: rsa2048PssKeyPair.fingerprint,
        public_key: rsa2048PssKeyPair.public_key,
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
        message: "Failed to encrypt RSA-PSS-2048 key pair with AES-GCM-256",
        cause: error
      });
    }
  }

  /**
   * Decrypt an RSA-PSS-2048 key pair with an AES-GCM-256 symmetric key
   */
  static async decryptRSA2048PSSKeyPairWithAESGCM256(
    encryptedKeyPair: any,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<RSAPSS2048AsymmetricKey, CryptographicError>> {
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
        format: KEY_SCHEMAS.ASYMMETRIC.RSA_PSS_2048,
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
        message: "Failed to decrypt RSA-PSS-2048 key pair with AES-GCM-256",
        cause: error
      });
    }
  }

  /**
   * Encrypt an RSA-PSS-2048 key pair with an RSA-OAEP-2048 key pair
   */
  static async encryptRSA2048PSSKeyPairWithRSA2048OAEP(
    rsa2048PssKeyPair: RSAPSS2048AsymmetricKey,
    rsa2048OaepKeyPair: any
  ): Promise<Result<RSAOAEP2048EncryptsRSAPSS2048Key, CryptographicError>> {
    try {
      // Generate AES key for hybrid encryption
      const aesKey = randomBytes(32);
      const privateKeyData = CryptoUtils.decodeBase64(rsa2048PssKeyPair.private_key.key.data);

      // Encrypt private key with AES
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
      const encryptedPrivateKey = Buffer.concat([cipher.update(privateKeyData), cipher.final()]);
      const tag = cipher.getAuthTag();

      // Encrypt AES key with RSA-OAEP
      const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${CryptoUtils.decodeBase64(rsa2048OaepKeyPair.public_key.key.data)}\n-----END PUBLIC KEY-----`;
      const encryptedAesKey = publicEncrypt(publicKeyPem, aesKey);

      // Create hybrid data structure
      const hybridData = {
        encryptedAesKey: CryptoUtils.encodeBase64(encryptedAesKey),
        encryptedPrivateKey: CryptoUtils.encodeBase64(encryptedPrivateKey),
        iv: CryptoUtils.encodeBase64(iv),
        tag: CryptoUtils.encodeBase64(tag),
        algorithm: "AES-GCM-256",
        version: "1.0.0"
      };

      const hybridDataJson = JSON.stringify(hybridData);
      const hybridDataBase64 = CryptoUtils.encodeBase64(new TextEncoder().encode(hybridDataJson));

      return ok({
        format: ENCRYPTED_KEY_SCHEMAS.ASYMMETRIC_ENCRYPTS_ASYMMETRIC.RSA_OAEP_2048_ENCRYPTS_RSA_PSS_2048,
        fingerprint: rsa2048PssKeyPair.fingerprint,
        public_key: rsa2048PssKeyPair.public_key,
        private_key: {
          format: KEY_SCHEMAS.ENCODING.PKCS8,
          key: {
            format: ENCRYPTED_DATA_SCHEMAS.ASYMMETRIC.RSA_OAEP_2048,
            encrypted_data: CryptoUtils.createEncodedStringContainer(new TextEncoder().encode(hybridDataBase64)),
            fingerprint: rsa2048OaepKeyPair.fingerprint
          }
        },
        encryption_key_fingerprint: rsa2048OaepKeyPair.fingerprint
      });
    } catch (error) {
      return err({
        code: "ENCRYPTION_FAILED",
        message: "Failed to encrypt RSA-2048 PSS key pair with RSA-2048 OAEP (hybrid approach)",
        cause: error
      });
    }
  }

  /**
   * Decrypt an RSA-PSS-2048 key pair encrypted with an RSA-OAEP-2048 key pair (hybrid approach)
   */
  static async decryptRSA2048PSSKeyPairWithRSA2048OAEP(
    encryptedKeyPair: RSAOAEP2048EncryptsRSAPSS2048Key,
    rsa2048OaepKeyPair: any
  ): Promise<Result<RSAPSS2048AsymmetricKey, CryptographicError>> {
    try {
      // Extract hybrid data
      const hybridDataBase64 = CryptoUtils.decodeBase64(encryptedKeyPair.private_key.key.encrypted_data.data);
      const hybridDataJson = new TextDecoder().decode(hybridDataBase64);
      const hybridData = JSON.parse(hybridDataJson);

      // Decrypt AES key with RSA-OAEP
      const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${CryptoUtils.decodeBase64(rsa2048OaepKeyPair.private_key.key.data)}\n-----END PRIVATE KEY-----`;
      const encryptedAesKey = CryptoUtils.decodeBase64(hybridData.encryptedAesKey);
      const aesKey = privateDecrypt(privateKeyPem, encryptedAesKey);

      // Decrypt private key with AES
      const encryptedPrivateKey = CryptoUtils.decodeBase64(hybridData.encryptedPrivateKey);
      const iv = CryptoUtils.decodeBase64(hybridData.iv);
      const tag = CryptoUtils.decodeBase64(hybridData.tag);

      const decipher = createDecipheriv('aes-256-gcm', aesKey, iv);
      decipher.setAuthTag(tag);
      const decryptedPrivateKey = Buffer.concat([decipher.update(encryptedPrivateKey), decipher.final()]);
      const privateKeyBase64 = CryptoUtils.encodeBase64(decryptedPrivateKey);

      return ok({
        format: KEY_SCHEMAS.ASYMMETRIC.RSA_PSS_2048,
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
        message: "Failed to decrypt RSA-PSS-2048 key pair with RSA-OAEP-2048 (hybrid approach)",
        cause: error
      });
    }
  }

  /**
   * Encrypt an AES-GCM-256 symmetric key with an RSA-OAEP-2048 key pair
   */
  static async encryptAESGCM256SymmetricKeyWithRSA2048OAEP(
    symmetricKey: AESGCM256SymmetricKey,
    rsa2048OaepKeyPair: any
  ): Promise<Result<RSAOAEP2048EncryptsAESGCM256Key, CryptographicError>> {
    try {
      const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${CryptoUtils.decodeBase64(rsa2048OaepKeyPair.public_key.key.data)}\n-----END PUBLIC KEY-----`;
      const keyData = CryptoUtils.decodeBase64(symmetricKey.key.data);
      const encryptedKey = publicEncrypt(publicKeyPem, keyData);

      return ok({
        format: ENCRYPTED_KEY_SCHEMAS.ASYMMETRIC_ENCRYPTS_SYMMETRIC.RSA_OAEP_2048_ENCRYPTS_AES_GCM_256,
        fingerprint: symmetricKey.fingerprint,
        key: {
          format: ENCRYPTED_DATA_SCHEMAS.ASYMMETRIC.RSA_OAEP_2048,
          encrypted_data: CryptoUtils.createEncodedStringContainer(encryptedKey),
          fingerprint: rsa2048OaepKeyPair.fingerprint
        }
      });
    } catch (error) {
      return err({
        code: "ENCRYPTION_FAILED",
        message: "Failed to encrypt AES-GCM-256 symmetric key with RSA-2048 OAEP",
        cause: error
      });
    }
  }

  /**
   * Encrypt a Base64-encoded private key with an RSA-OAEP-2048 key pair (SEK)
   */
  static async encryptBase64PrivateKeyWithRSA2048OAEP(
    privateKeyBase64: string,
    sekKeyPair: any
  ): Promise<Result<{
    encryptedPrivateKeyBase64: string;
    algorithm: string;
    version: string;
  }, CryptographicError>> {
    try {
      const publicKeyDer = Buffer.from(CryptoUtils.decodeBase64(sekKeyPair.public_key.key.data));
      const publicKey = require('crypto').createPublicKey({
        key: publicKeyDer,
        format: 'der',
        type: 'spki'
      });
      const privateKeyData = CryptoUtils.decodeBase64(privateKeyBase64);
      const encryptedKey = publicEncrypt({
        key: publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      }, privateKeyData);

      return ok({
        encryptedPrivateKeyBase64: CryptoUtils.encodeBase64(encryptedKey),
        algorithm: "RSA-OAEP-2048",
        version: "1.0.0"
      });
    } catch (error) {
      return err({
        code: "ENCRYPTION_FAILED",
        message: "Failed to encrypt Base64 private key with RSA-2048 OAEP",
        cause: error
      });
    }
  }
}
