import { mod, randomScalar, powBigInt } from '../../../../../ports-and-adapters/threshold-signature/cryptographic-utils/field-arithmetic';

describe('Field Arithmetic Utilities', () => {
  describe('mod', () => {
    it('should perform modular reduction correctly', () => {
      const modulus = 7n;

      expect(mod(10n, modulus)).toBe(3n); // 10 % 7 = 3
      expect(mod(7n, modulus)).toBe(0n);  // 7 % 7 = 0
      expect(mod(3n, modulus)).toBe(3n);  // 3 % 7 = 3
      expect(mod(-3n, modulus)).toBe(4n); // -3 % 7 = 4 (positive result)
    });

    it('should handle large numbers with default BLS modulus', () => {
      const largeNum = 1234567890123456789012345678901234567890n;
      const result = mod(largeNum);

      expect(result).toBeGreaterThanOrEqual(0n);
      expect(result).toBeLessThan(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n);
    });
  });

  describe('randomScalar', () => {
    it('should generate a scalar within the BLS field', () => {
      const scalar = randomScalar();

      expect(scalar).toBeGreaterThanOrEqual(0n);
      expect(scalar).toBeLessThan(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n);
      expect(typeof scalar).toBe('bigint');
    });

    it('should generate different values on multiple calls', () => {
      const scalar1 = randomScalar();
      const scalar2 = randomScalar();

      // Note: There's a small chance this could fail due to randomness,
      // but it's extremely unlikely
      expect(scalar1).not.toBe(scalar2);
    });
  });

  describe('powBigInt', () => {
    it('should calculate power correctly', () => {
      expect(powBigInt(2n, 3n)).toBe(8n);    // 2^3 = 8
      expect(powBigInt(5n, 0n)).toBe(1n);    // 5^0 = 1
      expect(powBigInt(3n, 4n)).toBe(81n);   // 3^4 = 81
    });

    it('should handle modular arithmetic', () => {
      const modulus = 7n;
      const base = 3n;
      const exp = 4n;

      // 3^4 = 81, 81 % 7 = 4
      const result = powBigInt(base, exp);
      expect(mod(result, modulus)).toBe(4n);
    });

    it('should handle large exponents efficiently', () => {
      const base = 2n;
      const exp = 100n;
      const result = powBigInt(base, exp);

      // 2^100 is a very large number
      expect(result).toBe(2n ** 100n);
    });
  });
});
