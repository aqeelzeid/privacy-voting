import { calculateThreshold } from '../../../../../ports-and-adapters/threshold-signature/port';

describe('Threshold Signature Port Utilities', () => {
  describe('calculateThreshold', () => {
    it('should calculate ONE_OVER_N threshold correctly', () => {
      expect(calculateThreshold('ONE_OVER_N', 3)).toBe(1);
      expect(calculateThreshold('ONE_OVER_N', 5)).toBe(1);
      expect(calculateThreshold('ONE_OVER_N', 10)).toBe(1);
      expect(calculateThreshold('ONE_OVER_N', 1)).toBe(1);
    });

    it('should calculate MAJORITY threshold correctly', () => {
      expect(calculateThreshold('MAJORITY', 3)).toBe(3);  // ceil(3/2) + 1 = 2 + 1 = 3
      expect(calculateThreshold('MAJORITY', 4)).toBe(3);  // ceil(4/2) + 1 = 2 + 1 = 3
      expect(calculateThreshold('MAJORITY', 5)).toBe(4);  // ceil(5/2) + 1 = 3 + 1 = 4
      expect(calculateThreshold('MAJORITY', 6)).toBe(4);  // ceil(6/2) + 1 = 3 + 1 = 4
    });

    it('should calculate ALL threshold correctly', () => {
      expect(calculateThreshold('ALL', 3)).toBe(3);
      expect(calculateThreshold('ALL', 5)).toBe(5);
      expect(calculateThreshold('ALL', 1)).toBe(1);
      expect(calculateThreshold('ALL', 10)).toBe(10);
    });

    it('should throw error for unknown mode', () => {
      expect(() => calculateThreshold('UNKNOWN' as any, 3)).toThrow('Unknown mode: UNKNOWN');
    });

    it('should handle edge cases', () => {
      // Test with different participant counts
      expect(calculateThreshold('MAJORITY', 1)).toBe(2);  // ceil(1/2) + 1 = 1 + 1 = 2
      expect(calculateThreshold('MAJORITY', 2)).toBe(2);  // ceil(2/2) + 1 = 1 + 1 = 2
    });
  });
});
