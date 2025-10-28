import { generateUserAccount, AccountSchemaWithoutAccountId } from './account/account';
import { createCryptographicAdapter } from './ports-and-adapters/cryptographic-adapter';
import { createHashingAdapter } from './ports-and-adapters/hashing-adapter';
import {NodePersistenceAdapter} from './ports-and-adapters/persistence-adapter'

// Step 1: Create 7 Users accounts
const users = [
  {
    name: 'John Doe',
    email: 'john.doe@example.com',
    password: 'password123'
  },
  {
    name: 'Bob Johnson',
    email: 'bob.johnson@example.com',
    password: 'password123'
  },
  {
    name: 'Charlie Brown',
    email: 'charlie.brown@example.com',
    password: 'password123'
  },
  {
    name: 'Diana Prince',
    email: 'diana.prince@example.com',
    password: 'password123'
  },
  {
    name: 'Edward Wilson',
    email: 'edward.wilson@example.com',
    password: 'password123'
  },
  {
    name: 'Fiona Gallagher',
    email: 'fiona.gallagher@example.com',
    password: 'password123'
  },
  {
    name: 'George Miller',
    email: 'george.miller@example.com',
    password: 'password123'
  }
];

interface User {
  name: string;
  email: string;
  password: string;
}

interface UserWithAccount extends User {
  account: AccountSchemaWithoutAccountId;
}

/**
 * Creates cryptographic accounts for all users in the system
 * @param users Array of users to create accounts for
 * @returns Promise resolving to array of users with their cryptographic accounts
 */
async function createAccountsForUsers(users: User[]): Promise<UserWithAccount[]> {
  console.log('🏗️  Creating cryptographic accounts for users...');

  // Create adapters
  const cryptoAdapter = createCryptographicAdapter();
  const hashingAdapter = createHashingAdapter();
  const persistanceAdapter = new NodePersistenceAdapter();

  const usersWithAccounts: UserWithAccount[] = [];

  for (const user of users) {
    // Generate cryptographic account (quiet operation)
    const accountResult = await generateUserAccount({
      cryptographicPort: cryptoAdapter,
      hashingPort: hashingAdapter,
      persistencePort: persistanceAdapter
    }, {
      email: user.email,
      password: user.password
    });

    if (!accountResult.ok) {
      console.error(`❌ Failed to create account for ${user.name}:`, accountResult.error);
      throw new Error(`Account creation failed for ${user.name}: ${accountResult.error.message}`);
    }

    const userWithAccount: UserWithAccount = {
      ...user,
      account: accountResult.value
    };

    usersWithAccounts.push(userWithAccount);
  }

  console.log(`✅ Successfully created ${usersWithAccounts.length} cryptographic accounts!\n`);
  return usersWithAccounts;
}

/**
 * Main execution function
 */
async function main() {
  try {
    console.log('Privacy Preserving Voting System Proof Of Concept\n');

    const usersWithAccounts = await createAccountsForUsers(users);
    usersWithAccounts.forEach((user, index) => {
      console.log(`${index + 1}. ${user.name}`);
    });

    console.log('\n🔐 All accounts created with hierarchical key encryption');
    console.log('   (Password → PDK → KEK → (SEK, SSK))');


    
  } catch (error) {
    console.error('💥 Fatal error', error);
    process.exit(1);
  }
}

// Execute the main function
main();