import { CryptographicPort } from './cryptographic/port';
import { HashingPort } from './hashing-port';
import { PersistencePort } from './persistence-port';

export interface Dependencies {
  cryptographicPort: CryptographicPort;
  hashingPort: HashingPort;
  persistencePort: PersistencePort;
}
