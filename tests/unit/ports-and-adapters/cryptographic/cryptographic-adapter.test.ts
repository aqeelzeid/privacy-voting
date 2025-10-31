import { NodeCryptographicAdapter } from '../../../../ports-and-adapters/cryptographic/node-adapter';
import { CryptographicError } from '../../../../ports-and-adapters/cryptographic/port';

describe('NodeCryptographicAdapter', () => {
  let adapter: NodeCryptographicAdapter;

  beforeEach(() => {
    adapter = new NodeCryptographicAdapter();
  });

  describe('generatePBKDF2PasswordDerivedKey', () => {
    it('should generate a PBKDF2 password-derived key', async () => {
      const password = 'test-password';
      const result = await adapter.generatePBKDF2PasswordDerivedKey(password);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.format).toBe('https://abiogenesys.io/containers/keys/pbkdf2');
        expect(result.value.algorithm).toBe('pbkdf2');
        expect(result.value.iterations).toBe(100000);
        expect(result.value.key_length).toBe(256);
        expect(result.value.derived_key.data).toBeDefined();
        expect(result.value.fingerprint.data).toBeDefined();
      }
    });
  });

  describe('generatePBKDF2PasswordDerivedKeyWithParameters', () => {
    it('should generate a PBKDF2 password-derived key with custom parameters', async () => {
      const password = 'test-password';
      const salt = 'dGVzdC1zYWx0'; // base64 encoded 'test-salt'
      const iterations = 50000;

      const result = await adapter.generatePBKDF2PasswordDerivedKeyWithParameters(password, salt, iterations);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.iterations).toBe(iterations);
        expect(result.value.salt.data).toBe(salt);
      }
    });
  });

  describe('getAESGCM256SymmetricKeyFromPBKDF2PasswordDerivedKey', () => {
    it('should derive AES key from PBKDF2 password-derived key', async () => {
      const password = 'test-password';

      // First generate the PDK
      const pdkResult = await adapter.generatePBKDF2PasswordDerivedKey(password);
      expect(pdkResult.ok).toBe(true);

      if (pdkResult.ok) {
        // Then derive the AES key
        const aesResult = await adapter.getAESGCM256SymmetricKeyFromPBKDF2PasswordDerivedKey(pdkResult.value, password);

        expect(aesResult.ok).toBe(true);
        if (aesResult.ok) {
          expect(aesResult.value.format).toBe('https://abiogenesys.io/keys/symmetric/aes-gcm-256');
          expect(aesResult.value.key.data).toBeDefined();
          expect(aesResult.value.fingerprint.data).toBeDefined();
        }
      }
    });

    it('should fail with invalid password', async () => {
      const password = 'test-password';

      // Generate PDK with one password
      const pdkResult = await adapter.generatePBKDF2PasswordDerivedKey(password);
      expect(pdkResult.ok).toBe(true);

      if (pdkResult.ok) {
        // Try to derive with different password
        const aesResult = await adapter.getAESGCM256SymmetricKeyFromPBKDF2PasswordDerivedKey(pdkResult.value, 'wrong-password');

        expect(aesResult.ok).toBe(false);
        if (!aesResult.ok) {
          expect((aesResult.error as CryptographicError).code).toBe('INVALID_PASSWORD');
        }
      }
    });
  });

  describe('generateAESGCM256KeyPair', () => {
    it('should generate an AES-GCM-256 symmetric key', async () => {
      const result = await adapter.generateAESGCM256KeyPair();

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.format).toBe('https://abiogenesys.io/keys/symmetric/aes-gcm-256');
        expect(result.value.key.data).toBeDefined();
        expect(result.value.fingerprint.data).toBeDefined();
      }
    });
  });

  describe('generateRSA2048OAEPKeyPair', () => {
    it('should generate an RSA-2048 OAEP key pair', async () => {
      const result = await adapter.generateRSA2048OAEPKeyPair();

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.format).toBe('https://abiogenesys.io/keys/asymmetric/rsa-oaep-2048');
        expect(result.value.public_key.format).toBe('https://abiogenesys.io/keys/encoding/spki');
        expect(result.value.private_key.format).toBe('https://abiogenesys.io/keys/encoding/pkcs8');
        expect(result.value.fingerprint.data).toBeDefined();
      }
    });
  });

  describe('generateRSA2048PSSKeyPair', () => {
    it('should generate an RSA-2048 PSS key pair', async () => {
      const result = await adapter.generateRSA2048PSSKeyPair();

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.format).toBe('https://abiogenesys.io/keys/asymmetric/rsa-pss-2048');
        expect(result.value.public_key.format).toBe('https://abiogenesys.io/keys/encoding/spki');
        expect(result.value.private_key.format).toBe('https://abiogenesys.io/keys/encoding/pkcs8');
        expect(result.value.fingerprint.data).toBeDefined();
      }
    });
  });

  describe('generateUUID', () => {
    it('should generate a valid UUID', async () => {
      const result = await adapter.generateUUID();

      expect(result.ok).toBe(true);
      if (result.ok) {
        // UUID v4 regex pattern
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        expect(uuidRegex.test(result.value)).toBe(true);
      }
    });
  });

  describe('generateOTPCode', () => {
    it('should generate an OTP code of specified length', async () => {
      const length = 6;
      const result = await adapter.generateOTPCode(length);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value).toBeGreaterThanOrEqual(0);
        expect(result.value).toBeLessThan(Math.pow(10, length));
        expect(result.value.toString().length).toBeLessThanOrEqual(length);
      }
    });
  });

  describe('encryptDataWithAESGCM256 and decryptDataWithAESGCM256', () => {
    it('should encrypt and decrypt data correctly', async () => {
      const data = new TextEncoder().encode('Hello, World!');
      const keyResult = await adapter.generateAESGCM256KeyPair();
      expect(keyResult.ok).toBe(true);

      if (keyResult.ok) {
        const encryptResult = await adapter.encryptDataWithAESGCM256(data, keyResult.value);
        expect(encryptResult.ok).toBe(true);

        if (encryptResult.ok) {
          const decryptResult = await adapter.decryptDataWithAESGCM256(encryptResult.value, keyResult.value);
          expect(decryptResult.ok).toBe(true);

          if (decryptResult.ok) {
            const decryptedText = new TextDecoder().decode(decryptResult.value);
            expect(decryptedText).toBe('Hello, World!');
          }
        }
      }
    });
  });

  describe('encryptWalletDataWithAESGCM256 and decryptWalletDataWithAESGCM256', () => {
    it('should encrypt and decrypt wallet data correctly', async () => {
      const walletData = '{"key": "value"}';
      const keyResult = await adapter.generateAESGCM256KeyPair();
      expect(keyResult.ok).toBe(true);

      if (keyResult.ok) {
        const encryptResult = await adapter.encryptWalletDataWithAESGCM256(walletData, keyResult.value);
        expect(encryptResult.ok).toBe(true);

        if (encryptResult.ok) {
          const decryptResult = await adapter.decryptWalletDataWithAESGCM256(encryptResult.value, keyResult.value);
          expect(decryptResult.ok).toBe(true);

          if (decryptResult.ok) {
            expect(decryptResult.value).toBe(walletData);
          }
        }
      }
    });
  });

  describe('encryptDataWithHybridAESGCM256 and decryptDataWithHybridAESGCM256', () => {
    it('should encrypt and decrypt data with hybrid encryption', async () => {
      const data = 'SGVsbG8sIFdvcmxkIQ=='; // base64 encoded 'Hello, World!'
      const keyResult = await adapter.generateRSA2048OAEPKeyPair();
      expect(keyResult.ok).toBe(true);

      if (keyResult.ok) {
        const encryptResult = await adapter.encryptDataWithHybridAESGCM256(data, keyResult.value);
        expect(encryptResult.ok).toBe(true);

        if (encryptResult.ok) {
          const decryptResult = await adapter.decryptDataWithHybridAESGCM256(encryptResult.value, keyResult.value);
          expect(decryptResult.ok).toBe(true);

          if (decryptResult.ok) {
            expect(decryptResult.value).toBe(data);
          }
        }
      }
    });
  });
});
