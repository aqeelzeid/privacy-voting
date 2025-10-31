import { EncodedStringContainer, HashedStringContainer } from '../../../account/account';
import {
  ENCODED_STRING_SCHEMAS,
  HASH_SCHEMAS,
} from '../../../account/namespace';

/**
 * Common utilities for cryptographic operations
 */
export class CryptoUtils {
  static encodeBase64(data: Uint8Array): string {
    return Buffer.from(data).toString('base64');
  }

  static decodeBase64(data: string): Uint8Array {
    return new Uint8Array(Buffer.from(data, 'base64'));
  }

  static createEncodedStringContainer(data: Uint8Array): EncodedStringContainer {
    return {
      encoding: 'BASE64_STANDARD_PADDED' as keyof typeof ENCODED_STRING_SCHEMAS,
      data: this.encodeBase64(data)
    };
  }

  static generateRandomBytes(length: number): Uint8Array {
    return new Uint8Array(require('crypto').randomBytes(length));
  }

  static generateRandomString(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  static createHashedStringContainer(algorithm: keyof typeof HASH_SCHEMAS, data: string): HashedStringContainer {
    return {
      algorithm,
      encoding: 'BASE64_STANDARD_PADDED' as keyof typeof ENCODED_STRING_SCHEMAS,
      data
    };
  }
}
