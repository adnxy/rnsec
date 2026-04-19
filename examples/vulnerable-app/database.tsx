import Realm from 'realm';

// Rule: Realm database storing sensitive data without protection
export async function openUserDatabase() {
  // Storing user credentials without key
  const realm = await Realm.open({
    schema: [{ name: 'UserCredential', properties: { token: 'string', account: 'string' } }],
  });
  return realm;
}
