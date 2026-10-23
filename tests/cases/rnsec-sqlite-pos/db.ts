import * as SQLite from 'expo-sqlite';

const db = SQLite.openDatabaseSync('app.db');

export async function search(query: string) {
  return db.getAllAsync(`SELECT * FROM notes WHERE title LIKE '%${query}%'`);
}

export async function remove(rowKey: string, flag: string) {
  await db.runAsync('DELETE FROM notes WHERE k = ' + rowKey + ' AND f = ?', [flag]);
}

const TABLE = 'notes';
export function all() {
  return db.getAllAsync(`SELECT * FROM ${TABLE}`);
}
