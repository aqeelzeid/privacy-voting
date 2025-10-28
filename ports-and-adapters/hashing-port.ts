import { Result } from '../error';
import { HashedStringContainer } from '../account/account';

export interface HashingPort {
  sha256(data: string): Promise<Result<HashedStringContainer, unknown>>;
}
