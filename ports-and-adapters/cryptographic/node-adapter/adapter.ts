import { CryptographicPort, CryptographicError } from '../port';
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
  EncodedStringContainer,
  HashedStringContainer
} from '../../../account/account';
import { PublicKeyContainer } from '../../threshold-signature/port';
import { Result } from '../../../error';
import { KeyGeneration } from './key-generation';
import { AESOperations } from './aes-operations';
import { RSAOperations } from './rsa-operations';
import { LegacyOperations } from './legacy';

/**
 * Node.js cryptographic adapter implementation using native crypto module
 * This adapter composes various cryptographic operation modules
 */
export class NodeCryptographicAdapter implements CryptographicPort {
  // Key generation methods
  async generatePBKDF2PasswordDerivedKey(password: string): Promise<Result<PBKDF2PasswordDerivedKey, CryptographicError>> {
    return KeyGeneration.generatePBKDF2PasswordDerivedKey(password);
  }

  async generatePBKDF2PasswordDerivedKeyWithParameters(
    password: string,
    salt: string,
    iterations: number
  ): Promise<Result<PBKDF2PasswordDerivedKey, CryptographicError>> {
    return KeyGeneration.generatePBKDF2PasswordDerivedKeyWithParameters(password, salt, iterations);
  }

  async getAESGCM256SymmetricKeyFromPBKDF2PasswordDerivedKey(
    passwordDerivedKey: PBKDF2PasswordDerivedKey,
    password: string
  ): Promise<Result<AESGCM256SymmetricKey, CryptographicError>> {
    return KeyGeneration.getAESGCM256SymmetricKeyFromPBKDF2PasswordDerivedKey(passwordDerivedKey, password);
  }

  async generateAESGCM256KeyPair(): Promise<Result<AESGCM256SymmetricKey, CryptographicError>> {
    return KeyGeneration.generateAESGCM256KeyPair();
  }

  async generateRSA2048OAEPKeyPair(): Promise<Result<RSAOAEP2048AsymmetricKey, CryptographicError>> {
    return KeyGeneration.generateRSA2048OAEPKeyPair();
  }

  async generateRSA2048PSSKeyPair(): Promise<Result<RSAPSS2048AsymmetricKey, CryptographicError>> {
    return KeyGeneration.generateRSA2048PSSKeyPair();
  }

  async generateUUID(): Promise<Result<string, CryptographicError>> {
    return KeyGeneration.generateUUID();
  }

  async generateOTPCode(length: number): Promise<Result<number, CryptographicError>> {
    return KeyGeneration.generateOTPCode(length);
  }

  // AES encryption/decryption methods
  async encryptPBKDF2PasswordDerivedKeyWithAESGCM256(
    passwordDerivedKey: PBKDF2PasswordDerivedKey,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256EncryptsAESGCM256Key, CryptographicError>> {
    return AESOperations.encryptPBKDF2PasswordDerivedKeyWithAESGCM256(passwordDerivedKey, symmetricKey);
  }

  async encryptAESGCM256SymmetricKeyWithAESGCM256(
    symmetricKeyToEncrypt: AESGCM256SymmetricKey,
    encryptionKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256EncryptsAESGCM256Key, CryptographicError>> {
    return AESOperations.encryptAESGCM256SymmetricKeyWithAESGCM256(symmetricKeyToEncrypt, encryptionKey);
  }

  async encryptRSA2048OAEPKeyPairWithAESGCM256(
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256EncryptsRSAOAEP2048Key, CryptographicError>> {
    return AESOperations.encryptRSA2048OAEPKeyPairWithAESGCM256(rsa2048OaepKeyPair, symmetricKey);
  }

  async encryptDataWithAESGCM256(
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
    return AESOperations.encryptDataWithAESGCM256(data, symmetricKey);
  }

  async decryptDataWithAESGCM256(
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
    return AESOperations.decryptDataWithAESGCM256(encryptedData, symmetricKey);
  }

  async encryptDataWithHybridAESGCM256(
    dataBase64: string,
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<HybridAESGCMEncryptedData, CryptographicError>> {
    return AESOperations.encryptDataWithHybridAESGCM256(dataBase64, rsa2048OaepKeyPair);
  }

  async decryptDataWithHybridAESGCM256(
    encryptedData: HybridAESGCMEncryptedData,
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<string, CryptographicError>> {
    return AESOperations.decryptDataWithHybridAESGCM256(encryptedData, rsa2048OaepKeyPair);
  }

  async encryptWalletDataWithAESGCM256(
    walletData: string,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCMSymmetricEncryptedData, CryptographicError>> {
    return AESOperations.encryptWalletDataWithAESGCM256(walletData, symmetricKey);
  }

  async decryptWalletDataWithAESGCM256(
    encryptedData: AESGCMSymmetricEncryptedData,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<string, CryptographicError>> {
    return AESOperations.decryptWalletDataWithAESGCM256(encryptedData, symmetricKey);
  }

  async decryptAESGCM256SymmetricKeyWithAESGCM256(
    encryptedKey: AESGCM256EncryptsAESGCM256Key,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256SymmetricKey, CryptographicError>> {
    return AESOperations.decryptAESGCM256SymmetricKeyWithAESGCM256(encryptedKey, symmetricKey);
  }

  async decryptRSA2048OAEPKeyPairWithAESGCM256(
    encryptedKeyPair: AESGCM256EncryptsRSAOAEP2048Key,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<RSAOAEP2048AsymmetricKey, CryptographicError>> {
    return AESOperations.decryptRSA2048OAEPKeyPairWithAESGCM256(encryptedKeyPair, symmetricKey);
  }

  async verifyDecryptedKeyPair(
    decryptedKeyPair: RSAOAEP2048AsymmetricKey,
    publicKey: { format: string; key: string }
  ): Promise<Result<boolean, CryptographicError>> {
    return AESOperations.verifyDecryptedKeyPair(decryptedKeyPair, publicKey);
  }

  // RSA encryption/decryption methods
  async encryptRSA2048PSSKeyPairWithAESGCM256(
    rsa2048PssKeyPair: RSAPSS2048AsymmetricKey,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<AESGCM256EncryptsRSAPSS2048Key, CryptographicError>> {
    return RSAOperations.encryptRSA2048PSSKeyPairWithAESGCM256(rsa2048PssKeyPair, symmetricKey);
  }

  async decryptRSA2048PSSKeyPairWithAESGCM256(
    encryptedKeyPair: AESGCM256EncryptsRSAPSS2048Key,
    symmetricKey: AESGCM256SymmetricKey
  ): Promise<Result<RSAPSS2048AsymmetricKey, CryptographicError>> {
    return RSAOperations.decryptRSA2048PSSKeyPairWithAESGCM256(encryptedKeyPair, symmetricKey);
  }

  async encryptRSA2048PSSKeyPairWithRSA2048OAEP(
    rsa2048PssKeyPair: RSAPSS2048AsymmetricKey,
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<RSAOAEP2048EncryptsRSAPSS2048Key, CryptographicError>> {
    return RSAOperations.encryptRSA2048PSSKeyPairWithRSA2048OAEP(rsa2048PssKeyPair, rsa2048OaepKeyPair);
  }

  async decryptRSA2048PSSKeyPairWithRSA2048OAEP(
    encryptedKeyPair: RSAOAEP2048EncryptsRSAPSS2048Key,
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<RSAPSS2048AsymmetricKey, CryptographicError>> {
    return RSAOperations.decryptRSA2048PSSKeyPairWithRSA2048OAEP(encryptedKeyPair, rsa2048OaepKeyPair);
  }

  async encryptAESGCM256SymmetricKeyWithRSA2048OAEP(
    symmetricKey: AESGCM256SymmetricKey,
    rsa2048OaepKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<RSAOAEP2048EncryptsAESGCM256Key, CryptographicError>> {
    return RSAOperations.encryptAESGCM256SymmetricKeyWithRSA2048OAEP(symmetricKey, rsa2048OaepKeyPair);
  }

  async encryptBase64PrivateKeyWithRSA2048OAEP(
    privateKeyBase64: string,
    sekKeyPair: RSAOAEP2048AsymmetricKey
  ): Promise<Result<{
    encryptedPrivateKeyBase64: string;
    algorithm: string;
    version: string;
  }, CryptographicError>> {
    return RSAOperations.encryptBase64PrivateKeyWithRSA2048OAEP(privateKeyBase64, sekKeyPair);
  }

  // Legacy methods for threshold signature compatibility
  async encryptWithRSAOAEP(
    data: Uint8Array,
    publicKey: PublicKeyContainer
  ): Promise<Result<EncodedStringContainer, unknown>> {
    return LegacyOperations.encryptWithRSAOAEP(data, publicKey);
  }

  async decryptWithRSAOAEP(
    encryptedData: EncodedStringContainer,
    privateKey: AESGCM256EncryptsRSAOAEP2048Key,
    kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer }
  ): Promise<Result<Uint8Array, unknown>> {
    return LegacyOperations.decryptWithRSAOAEP(encryptedData, privateKey, kek);
  }

  async signWithRSAPSS(
    data: Uint8Array,
    privateKey: AESGCM256EncryptsRSAOAEP2048Key,
    kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer }
  ): Promise<Result<string, unknown>> {
    return LegacyOperations.signWithRSAPSS(data, privateKey, kek);
  }

  async verifyRSAPSSSignature(
    data: Uint8Array,
    signature: string,
    publicKey: PublicKeyContainer
  ): Promise<Result<boolean, unknown>> {
    return LegacyOperations.verifyRSAPSSSignature(data, signature, publicKey);
  }
}
