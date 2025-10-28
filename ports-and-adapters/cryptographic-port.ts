import { Result } from '../error';
import {
  HashedStringContainer,
  PasswordDerivedKey,
  AESGCM256EncryptedData,
  SymmetricEncryptsSymmetricKey,
  AESGCM256EncryptsRSAOAEP2048Key,
  EncodedStringContainer
} from '../account/account';

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
