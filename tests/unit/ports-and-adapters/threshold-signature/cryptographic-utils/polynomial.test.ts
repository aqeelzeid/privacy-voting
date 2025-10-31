import { randomPolynomial, evalPoly } from '../../../../../ports-and-adapters/threshold-signature/cryptographic-utils/polynomial';

describe('Polynomial Utilities', () => {
  describe('randomPolynomial', () => {
    it('should generate a polynomial with correct degree', () => {
      const degree = 3;
      const poly = randomPolynomial(degree);

      expect(poly).toHaveLength(degree + 1); // degree + 1 coefficients
      expect(Array.isArray(poly)).toBe(true);
    });

    it('should generate polynomials with bigint coefficients', () => {
      const poly = randomPolynomial(2);

      poly.forEach(coeff => {
        expect(typeof coeff).toBe('bigint');
        expect(coeff).toBeGreaterThanOrEqual(0n);
      });
    });

    it('should throw error for negative degree', () => {
      expect(() => randomPolynomial(-1)).toThrow('degree must be >= 0');
    });

    it('should handle degree 0', () => {
      const poly = randomPolynomial(0);

      expect(poly).toHaveLength(1); // constant term only
      expect(typeof poly[0]).toBe('bigint');
    });
  });

  describe('evalPoly', () => {
    it('should evaluate constant polynomial correctly', () => {
      const coeffs = [5n]; // f(x) = 5
      const result = evalPoly(coeffs, 3n);

      expect(result).toBe(5n);
    });

    it('should evaluate linear polynomial correctly', () => {
      const coeffs = [2n, 3n]; // f(x) = 3x + 2
      const result = evalPoly(coeffs, 4n);

      expect(result).toBe(14n); // 3*4 + 2 = 14
    });

    it('should evaluate quadratic polynomial correctly', () => {
      const coeffs = [1n, 2n, 3n]; // f(x) = 3x^2 + 2x + 1
      const result = evalPoly(coeffs, 2n);

      expect(result).toBe(17n); // 3*4 + 2*2 + 1 = 12 + 4 + 1 = 17
    });

    it('should handle polynomial evaluation at x=0', () => {
      const coeffs = [5n, 3n, 2n]; // f(x) = 2x^2 + 3x + 5
      const result = evalPoly(coeffs, 0n);

      expect(result).toBe(5n); // constant term
    });

    it('should handle polynomial evaluation at x=1', () => {
      const coeffs = [1n, 1n, 1n]; // f(x) = x^2 + x + 1
      const result = evalPoly(coeffs, 1n);

      expect(result).toBe(3n); // 1 + 1 + 1 = 3
    });

    it('should handle empty coefficients array', () => {
      // This should evaluate to 0 for any x
      const result = evalPoly([], 5n);

      expect(result).toBe(0n);
    });
  });
});
