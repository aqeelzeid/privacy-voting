import { randomScalar, mod } from './field-arithmetic';

/**
 * Generate a random polynomial of given degree with coefficients in the scalar field
 */
export function randomPolynomial(degree: number): bigint[] {
  if (degree < 0) throw new Error('degree must be >= 0');
  const coeffs: bigint[] = [];
  for (let i = 0; i <= degree; i++) coeffs.push(randomScalar());
  return coeffs;
}

/**
 * Evaluate polynomial at given point using Horner's method
 */
export function evalPoly(coeffs: bigint[], x: bigint): bigint {
  let res = 0n;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    res = mod(res * x + coeffs[i]);
  }
  return res;
}

