export const adminPassword = 'admin123';
export const config = { username: 'test', pwd: 'qwerty' };
export function login() {
  const loginUser = { email: 'test@example.com' };
  const headers = { Authorization: 'Bearer testabc123' };
  return { loginUser, headers };
}
