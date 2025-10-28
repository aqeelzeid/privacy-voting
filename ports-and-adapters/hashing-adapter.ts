import { createHash } from 'crypto';
import { Result, ok, err } from '../error';
import { HashingPort } from './hashing-port';
import { HashedStringContainer } from '../account/account';
import {
  HASH_SCHEMAS,
  ENCODED_STRING_SCHEMAS
} from '../account/namespace';

/**
 * Hashing adapter using Node.js crypto
 */
export class NodeCryptoHashingAdapter implements HashingPort {
  async sha256(data: string): Promise<Result<HashedStringContainer, unknown>> {
    try {
      const hash = createHash('sha256').update(data).digest();
      const encodedHash = Buffer.from(hash).toString('base64');

      const hashedStringContainer: HashedStringContainer = {
        algorithm: 'SHA256' as keyof typeof HASH_SCHEMAS,
        encoding: 'BASE64_STANDARD_PADDED' as keyof typeof ENCODED_STRING_SCHEMAS,
        data: encodedHash
      };

      return ok(hashedStringContainer);
    } catch (error) {
      return err(error);
    }
  }
}

/**
 * Factory function to create hashing adapter
 */
export function createHashingAdapter(): NodeCryptoHashingAdapter {
  return new NodeCryptoHashingAdapter();
}
