export function run(token, user, data, response, passwordStrength, tokenCount) {
  console.log('Password reset email sent');
  console.log('Token refreshed successfully');
  console.warn('Invalid password format');
  console.log(`Sending password reset to ${user.email}`);
  console.log('Opening profile', user.name);
  console.log(passwordStrength, tokenCount);
  console.log({ password: '***' });
  console.log('token:', 'redacted');
  console.log('token:', token);
  console.log(`token ${token}`);
  console.log('Auth token: ' + data.accessToken);
  console.log(user.credentials);
  console.log('user', { apiKey: data.key });
  console.error('refresh failed, userToken', userTokenValue());
  console.log('token:', response.data);
  console.log(data.headers['Authorization']);
  console.log({ password });
}
const password = 'p';
function userTokenValue() { return 1; }
