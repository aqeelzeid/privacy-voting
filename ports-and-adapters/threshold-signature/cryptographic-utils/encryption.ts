import { Result, ok } from '../../../error';
import { CryptographicPort } from '../../cryptographic/port';
import { PublicKeyContainer } from '../port';
import { AESGCM256EncryptsRSAOAEP2048Key, HashedStringContainer, EncodedStringContainer } from '../../../account/account';
import { ENCODED_STRING_SCHEMAS } from '../../../account/namespace';
import { bigintTo32Bytes, bytesToBigint } from './conversion';

/**
 * Encrypt a share for a specific recipient using RSA-OAEP
 */
export async function encryptShareWithRSA(
  share: bigint,
  recipientPublicKey: PublicKeyContainer,
  cryptographicPort: CryptographicPort
): Promise<Result<string, unknown>> {
  const shareBytes = bigintTo32Bytes(share);
  const result = await cryptographicPort.encryptWithRSAOAEP(shareBytes, recipientPublicKey);
  if (!result.ok) {
    return result;
  }
  return ok(result.value.data);
}

/**
 * Decrypt a share from a sender using RSA-OAEP
 */
export async function decryptShareWithRSA(
  encryptedShare: string,
  privateKey: AESGCM256EncryptsRSAOAEP2048Key,
  kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer },
  cryptographicPort: CryptographicPort
): Promise<Result<bigint, unknown>> {
  const encryptedData: EncodedStringContainer = {
    encoding: 'BASE64_STANDARD_PADDED' as keyof typeof ENCODED_STRING_SCHEMAS,
    data: encryptedShare
  };

  const result = await cryptographicPort.decryptWithRSAOAEP(encryptedData, privateKey, kek);
  if (!result.ok) {
    return result;
  }
  return ok(bytesToBigint(result.value));
}

/**
 * Sign commitments with RSA-PSS
 */
export async function signCommitments(
  commitments: string[],
  privateKey: AESGCM256EncryptsRSAOAEP2048Key,
  kek: { key: EncodedStringContainer; fingerprint: HashedStringContainer },
  cryptographicPort: CryptographicPort
): Promise<Result<string, unknown>> {
  const message = JSON.stringify({ commitments, timestamp: Date.now() });
  const messageBytes = new TextEncoder().encode(message);
  return await cryptographicPort.signWithRSAPSS(messageBytes, privateKey, kek);
}

/**
 * Verify commitment signature with RSA-PSS
 */
export async function verifyCommitmentSignature(
  commitments: string[],
  signature: string,
  publicKey: PublicKeyContainer,
  cryptographicPort: CryptographicPort
): Promise<Result<boolean, unknown>> {
  const message = JSON.stringify({ commitments, timestamp: Date.now() });
  const messageBytes = new TextEncoder().encode(message);
  return await cryptographicPort.verifyRSAPSSSignature(messageBytes, signature, publicKey);
}
