import { PointG1 } from '@noble/bls12-381';
import { PublicKeyContainer } from '../port';
import { EncodedStringContainer } from '../../../account/account';
import { ENCODED_STRING_SCHEMAS } from '../../../account/namespace';

/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert bigint to 32-byte big-endian Uint8Array
 */
export function bigintTo32Bytes(v: bigint): Uint8Array {
  const b = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
}

/**
 * Convert 32-byte big-endian Uint8Array to bigint
 */
export function bytesToBigint(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = 0; i < b.length; i++) v = (v << 8n) + BigInt(b[i]);
  return v;
}

/**
 * Convert PublicKeyContainer to Uint8Array (extract key bytes)
 */
export function spkiPublicKeyToBytes(publicKeyContainer: PublicKeyContainer): Uint8Array {
  // The PublicKeyContainer.key is already an EncodedStringContainer
  // For RSA keys, this should contain base64-encoded SPKI data
  // For now, decode as base64 (this is a simplified implementation)
  return new Uint8Array(Buffer.from(publicKeyContainer.key.data, 'base64'));
}

/**
 * Convert Uint8Array to base64-encoded string container
 */
export function bytesToBase64Container(bytes: Uint8Array): EncodedStringContainer {
  return {
    encoding: 'BASE64_STANDARD_PADDED' as keyof typeof ENCODED_STRING_SCHEMAS,
    data: Buffer.from(bytes).toString('base64')
  };
}

/**
 * Convert BLS G1 point to hex string
 */
export function pointG1ToHex(point: PointG1): string {
  return point.toHex(true);
}

/**
 * Convert hex string to BLS G1 point
 */
export function hexToPointG1(hex: string): PointG1 {
  return PointG1.fromHex(hex);
}
