import * as SQLite from 'expo-sqlite';

const db = SQLite.openDatabaseSync('app.db');
const TABLE = 'notes';

export async function init() {
  await db.execAsync(`CREATE TABLE IF NOT EXISTS ${TABLE} (id INTEGER PRIMARY KEY, title TEXT)`);
  await db.execAsync('PRAGMA journal_mode = WAL');
}
export function search(query: string) {
  return db.getAllAsync('SELECT * FROM notes WHERE title LIKE ?', [`%${query}%`]);
}
export function byIds(ids: number[]) {
  const ph = ids.map(() => '?').join(',');
  return db.getAllAsync(`SELECT * FROM notes WHERE id IN (${ph})`, ids);
}
export function page(limit: number) {
  return db.getAllAsync(`SELECT * FROM notes LIMIT ${Number(limit)}`);
}
