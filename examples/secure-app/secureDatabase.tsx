import Realm from 'realm';
import * as SQLite from 'expo-sqlite';

// SAFE: Realm database WITH encryption for user data
export async function openUserDatabase(encKey: ArrayBuffer) {
  const realm = await Realm.open({
    schema: [{ name: 'UserProfile', properties: { name: 'string', account: 'string' } }],
    encryptionKey: encKey,
  });
  return realm;
}

// SAFE: SQLite with SQLCipher encryption for account data
export function openAccountDatabase() {
  const db = SQLite.openDatabase('account_data.db');

  // Using sqlcipher for encryption
  db.transaction((tx) => {
    tx.executeSql("PRAGMA key = 'my-secure-encryption-key'");
    tx.executeSql(
      'CREATE TABLE IF NOT EXISTS user_sessions (id INTEGER PRIMARY KEY, token TEXT)'
    );
  });

  return db;
}

// SAFE: SQLite without sensitive context - should NOT trigger
export function openCacheDatabase() {
  const db = SQLite.openDatabase('cache.db');

  db.transaction((tx) => {
    tx.executeSql(
      'CREATE TABLE IF NOT EXISTS cache_entries (id INTEGER PRIMARY KEY, data TEXT, expiry INTEGER)'
    );
  });

  return db;
}
