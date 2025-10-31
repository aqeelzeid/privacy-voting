import { createCipheriv, createDecipheriv, publicEncrypt, privateDecrypt, createSign, createVerify } from 'crypto';
import { Result, ok, err } from '../../../error';
import { EncodedStringContainer, HashedStringContainer, AESGCM256EncryptsRSAOAEP2048Key } from '../../../account/account';
import { PublicKeyContainer } from '../../threshold-signature/port';
import { CryptoUtils } from './utils';

/**
 * Legacy methods for threshold signature compatibility
 */
export class LegacyOperations {
  /**
   * Encrypt data with RSA-OAEP (legacy method)
   */
  static async encryptWithRSAOAEP(
    data: Uint8Array,
    publicKey: PublicKeyContainer
  ): Promise<Result<EncodedStringContainer, unknown>> {
    try {
      const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${CryptoUtils.decodeBase64(publicKey.key.data)}\n-----END PUBLIC KEY-----`;
      const encrypted = publicEncrypt(publicKeyPem, data);
      return ok(CryptoUtils.createEncodedStringContainer(encrypted));
    } catch (error) {
      return err(error);
    }
  }

  /**
   * Decrypt data with RSA-OAEP (legacy method)
   */
  static async decryptWithRSAOAEP(
    encryptedData: EncodedStringContainer,
    privateKey: AESGCM256EncryptsRSAOAEP2048Key,
    kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer }
  ): Promise<Result<Uint8Array, unknown>> {
    try {
      // Decrypt the private key first
      const keyBuffer = CryptoUtils.decodeBase64(kek.key.data);
      const encryptedPrivateKey = CryptoUtils.decodeBase64(privateKey.private_key.key.encrypted_data.data);
      const iv = CryptoUtils.decodeBase64(privateKey.private_key.key.iv.data);
      const tag = CryptoUtils.decodeBase64(privateKey.private_key.key.tag.data);

      const decipher = createDecipheriv('aes-256-gcm', keyBuffer, iv);
      decipher.setAuthTag(tag);
      const decryptedPrivateKey = Buffer.concat([decipher.update(encryptedPrivateKey), decipher.final()]);

      const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${CryptoUtils.encodeBase64(decryptedPrivateKey)}\n-----END PRIVATE KEY-----`;
      const decrypted = privateDecrypt(privateKeyPem, CryptoUtils.decodeBase64(encryptedData.data));

      return ok(decrypted);
    } catch (error) {
      return err(error);
    }
  }

  /**
   * Sign data with RSA-PSS (legacy method)
   */
  static async signWithRSAPSS(
    data: Uint8Array,
    privateKey: AESGCM256EncryptsRSAOAEP2048Key,
    kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer }
  ): Promise<Result<string, unknown>> {
    try {
      // Decrypt the private key first
      const keyBuffer = CryptoUtils.decodeBase64(kek.key.data);
      const encryptedPrivateKey = CryptoUtils.decodeBase64(privateKey.private_key.key.encrypted_data.data);
      const iv = CryptoUtils.decodeBase64(privateKey.private_key.key.iv.data);
      const tag = CryptoUtils.decodeBase64(privateKey.private_key.key.tag.data);

      const decipher = createDecipheriv('aes-256-gcm', keyBuffer, iv);
      decipher.setAuthTag(tag);
      const decryptedPrivateKey = Buffer.concat([decipher.update(encryptedPrivateKey), decipher.final()]);

      const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${CryptoUtils.encodeBase64(decryptedPrivateKey)}\n-----END PRIVATE KEY-----`;
      const sign = createSign('RSA-PSS');
      sign.update(data);
      const signature = sign.sign({
        key: privateKeyPem,
        saltLength: 32
      });

      return ok(CryptoUtils.encodeBase64(signature));
    } catch (error) {
      return err(error);
    }
  }

  /**
   * Verify RSA-PSS signature (legacy method)
   */
  static async verifyRSAPSSSignature(
    data: Uint8Array,
    signature: string,
    publicKey: PublicKeyContainer
  ): Promise<Result<boolean, unknown>> {
    try {
      const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${CryptoUtils.decodeBase64(publicKey.key.data)}\n-----END PUBLIC KEY-----`;
      const verify = createVerify('RSA-PSS');
      verify.update(data);
      const isValid = verify.verify({
        key: publicKeyPem,
        saltLength: 32
      }, CryptoUtils.decodeBase64(signature));

      return ok(isValid);
    } catch (error) {
      return err(error);
    }
  }
}
