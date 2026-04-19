import * as SQLite from 'expo-sqlite';

// Rule: plain SQLite database storing sensitive data
export function openAccountDatabase() {
  // Opening SQLite database with user/payment data, no protection
  const db = SQLite.openDatabase('account_data.db');

  db.transaction((tx) => {
    tx.executeSql(
      'CREATE TABLE IF NOT EXISTS user_sessions (id INTEGER PRIMARY KEY, token TEXT, password TEXT)'
    );
  });

  return db;
}
