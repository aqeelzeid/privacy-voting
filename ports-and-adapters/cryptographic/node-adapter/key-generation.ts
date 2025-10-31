import { randomBytes, pbkdf2, generateKeyPair, createHash, randomUUID } from 'crypto';
import { promisify } from 'util';
import { Result, ok, err } from '../../../error';
import { CryptographicError } from '../port';
import {
  PBKDF2PasswordDerivedKey,
  AESGCM256SymmetricKey,
  RSAOAEP2048AsymmetricKey,
  RSAPSS2048AsymmetricKey,
} from '../../../account/account';
import {
  KEY_SCHEMAS,
} from '../../../account/namespace';
import { CryptoUtils } from './utils';

// Promisify crypto functions
const pbkdf2Async = promisify(pbkdf2);
const generateKeyPairAsync = promisify(generateKeyPair);

/**
 * Key generation operations
 */
export class KeyGeneration {
  /**
   * Generate a new PBKDF2 password-derived key
   */
  static async generatePBKDF2PasswordDerivedKey(password: string): Promise<Result<PBKDF2PasswordDerivedKey, CryptographicError>> {
    try {
      const passwordBuffer = new TextEncoder().encode(password);
      const salt = randomBytes(16);
      const iterations = 100000;
      const keyLength = 32;

      const derivedKey = await pbkdf2Async(password, salt, iterations, keyLength, 'sha256');

      const derivedKeyBase64 = CryptoUtils.encodeBase64(derivedKey);
      const saltBase64 = CryptoUtils.encodeBase64(salt);

      const fingerprintHash = await createHash('sha256').update(derivedKey).digest();
      const fingerprintBase64 = CryptoUtils.encodeBase64(fingerprintHash);

      return ok({
        format: KEY_SCHEMAS.PASSWORD_DERIVED.PBKDF2,
        algorithm: "pbkdf2",
        salt: CryptoUtils.createEncodedStringContainer(salt),
        iterations,
        key_length: 256,
        derived_key: CryptoUtils.createEncodedStringContainer(derivedKey),
        fingerprint: CryptoUtils.createHashedStringContainer('SHA256', fingerprintBase64)
      });
    } catch (error) {
      return err({
        code: "KEY_GENERATION_FAILED",
        message: "Failed to generate PBKDF2 password-derived key",
        cause: error
      });
    }
  }

  /**
   * Generate a PBKDF2 password-derived key using specific parameters
   */
  static async generatePBKDF2PasswordDerivedKeyWithParameters(
    password: string,
    salt: string,
    iterations: number
  ): Promise<Result<PBKDF2PasswordDerivedKey, CryptographicError>> {
    try {
      const passwordBuffer = new TextEncoder().encode(password);
      const saltBuffer = CryptoUtils.decodeBase64(salt);
      const keyLength = 32;

      const derivedKey = await pbkdf2Async(password, saltBuffer, iterations, keyLength, 'sha256');

      const derivedKeyBase64 = CryptoUtils.encodeBase64(derivedKey);

      const fingerprintHash = await createHash('sha256').update(derivedKey).digest();
      const fingerprintBase64 = CryptoUtils.encodeBase64(fingerprintHash);

      return ok({
        format: KEY_SCHEMAS.PASSWORD_DERIVED.PBKDF2,
        algorithm: "pbkdf2",
        salt: CryptoUtils.createEncodedStringContainer(saltBuffer),
        iterations,
        key_length: 256,
        derived_key: CryptoUtils.createEncodedStringContainer(derivedKey),
        fingerprint: CryptoUtils.createHashedStringContainer('SHA256', fingerprintBase64)
      });
    } catch (error) {
      return err({
        code: "KEY_GENERATION_FAILED",
        message: "Failed to generate PBKDF2 password-derived key with parameters",
        cause: error
      });
    }
  }

  /**
   * Get an AES-GCM-256 symmetric key from a PBKDF2 password-derived key
   */
  static async getAESGCM256SymmetricKeyFromPBKDF2PasswordDerivedKey(
    passwordDerivedKey: PBKDF2PasswordDerivedKey,
    password: string
  ): Promise<Result<AESGCM256SymmetricKey, CryptographicError>> {
    try {
      // Re-derive the key to verify the password
      const passwordBuffer = new TextEncoder().encode(password);
      const saltBuffer = CryptoUtils.decodeBase64(passwordDerivedKey.salt.data);

      const derivedKey = await pbkdf2Async(password, saltBuffer, passwordDerivedKey.iterations, 32, 'sha256');
      const derivedKeyBase64 = CryptoUtils.encodeBase64(derivedKey);

      if (derivedKeyBase64 !== passwordDerivedKey.derived_key.data) {
        return err({
          code: "INVALID_PASSWORD",
          message: "Password verification failed - derived key mismatch"
        });
      }

      const fingerprintHash = await createHash('sha256').update(derivedKey).digest();
      const fingerprintBase64 = CryptoUtils.encodeBase64(fingerprintHash);

      return ok({
        format: KEY_SCHEMAS.SYMMETRIC.AES_GCM_256,
        key: CryptoUtils.createEncodedStringContainer(derivedKey),
        fingerprint: CryptoUtils.createHashedStringContainer('SHA256', fingerprintBase64)
      });
    } catch (error) {
      return err({
        code: "KEY_GENERATION_FAILED",
        message: "Failed to derive AES-GCM-256 key from PBKDF2 password-derived key",
        cause: error
      });
    }
  }

  /**
   * Generate a new AES-GCM-256 symmetric key
   */
  static async generateAESGCM256KeyPair(): Promise<Result<AESGCM256SymmetricKey, CryptographicError>> {
    try {
      const key = randomBytes(32);
      const keyBase64 = CryptoUtils.encodeBase64(key);

      const fingerprintHash = await createHash('sha256').update(key).digest();
      const fingerprintBase64 = CryptoUtils.encodeBase64(fingerprintHash);

      return ok({
        format: KEY_SCHEMAS.SYMMETRIC.AES_GCM_256,
        key: CryptoUtils.createEncodedStringContainer(key),
        fingerprint: CryptoUtils.createHashedStringContainer('SHA256', fingerprintBase64)
      });
    } catch (error) {
      return err({
        code: "KEY_GENERATION_FAILED",
        message: "Failed to generate AES-GCM-256 symmetric key",
        cause: error
      });
    }
  }

  /**
   * Generate a new RSA-2048 OAEP key pair
   */
  static async generateRSA2048OAEPKeyPair(): Promise<Result<RSAOAEP2048AsymmetricKey, CryptographicError>> {
    try {
      const keyPair = await generateKeyPairAsync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'der'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'der'
        }
      });

      const publicKeyBuffer = keyPair.publicKey as Buffer;
      const privateKeyBuffer = keyPair.privateKey as Buffer;

      const fingerprintHash = await createHash('sha256').update(publicKeyBuffer).digest();
      const fingerprintBase64 = CryptoUtils.encodeBase64(fingerprintHash);

      return ok({
        format: KEY_SCHEMAS.ASYMMETRIC.RSA_OAEP_2048,
        fingerprint: CryptoUtils.createHashedStringContainer('SHA256', fingerprintBase64),
        public_key: {
          format: KEY_SCHEMAS.ENCODING.SPKI,
          key: CryptoUtils.createEncodedStringContainer(publicKeyBuffer)
        },
        private_key: {
          format: KEY_SCHEMAS.ENCODING.PKCS8,
          key: CryptoUtils.createEncodedStringContainer(privateKeyBuffer)
        }
      });
    } catch (error) {
      return err({
        code: "KEY_GENERATION_FAILED",
        message: "Failed to generate RSA-2048 OAEP key pair",
        cause: error
      });
    }
  }

  /**
   * Generate a new RSA-PSS-2048 key pair
   */
  static async generateRSA2048PSSKeyPair(): Promise<Result<RSAPSS2048AsymmetricKey, CryptographicError>> {
    try {
      const keyPair = await generateKeyPairAsync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'der'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'der'
        }
      });

      const publicKeyBuffer = keyPair.publicKey as Buffer;
      const privateKeyBuffer = keyPair.privateKey as Buffer;

      const fingerprintHash = await createHash('sha256').update(publicKeyBuffer).digest();
      const fingerprintBase64 = CryptoUtils.encodeBase64(fingerprintHash);

      return ok({
        format: KEY_SCHEMAS.ASYMMETRIC.RSA_PSS_2048,
        fingerprint: CryptoUtils.createHashedStringContainer('SHA256', fingerprintBase64),
        public_key: {
          format: KEY_SCHEMAS.ENCODING.SPKI,
          key: CryptoUtils.createEncodedStringContainer(publicKeyBuffer)
        },
        private_key: {
          format: KEY_SCHEMAS.ENCODING.PKCS8,
          key: CryptoUtils.createEncodedStringContainer(privateKeyBuffer)
        }
      });
    } catch (error) {
      return err({
        code: "KEY_GENERATION_FAILED",
        message: "Failed to generate RSA-2048 PSS key pair",
        cause: error
      });
    }
  }

  /**
   * Generate a new UUID
   */
  static async generateUUID(): Promise<Result<string, CryptographicError>> {
    try {
      return ok(randomUUID());
    } catch (error) {
      return err({
        code: "CRYPTO_API_ERROR",
        message: "Failed to generate UUID",
        cause: error
      });
    }
  }

  /**
   * Generate a new OTP code
   */
  static async generateOTPCode(length: number): Promise<Result<number, CryptographicError>> {
    try {
      const otp = Math.floor(Math.random() * Math.pow(10, length));
      return ok(otp);
    } catch (error) {
      return err({
        code: "CRYPTO_API_ERROR",
        message: "Failed to generate OTP code",
        cause: error
      });
    }
  }
}
