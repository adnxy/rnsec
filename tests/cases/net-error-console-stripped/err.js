export function logHeaders(error) {
  console.error('request failed', error.config.headers);
}
export function leakyAlert(error) {
  Alert.alert('Failed', error.message);
}
