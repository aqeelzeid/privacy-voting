import { CryptographicPort } from './cryptographic-port';
import { HashingPort } from './hashing-port';

export interface Dependencies {
  cryptographicPort: CryptographicPort;
  hashingPort: HashingPort;
}
