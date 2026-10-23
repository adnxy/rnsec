import { Alert } from 'react-native';

export function safeCatch(run) {
  try {
    run();
  } catch (error) {
    console.log(error.message);
    Alert.alert('Something went wrong');
  }
}
export function safeComment(run) {
  try {
    run();
  } catch (error) {
    // never show error.message to the user via Alert.alert
    Alert.alert('Something went wrong');
  }
}
export function stderrLike(stderr) {
  console.error(stderr.message);
}
export function leakyCatch(run) {
  try {
    run();
  } catch (e) {
    Alert.alert('Failed', e.message);
  }
}
export function leakyTemplate(run) {
  try {
    run();
  } catch (failure) {
    Alert.alert('Failed', `Reason: ${failure.stack}`);
  }
}
export function logError(error) {
  console.error(error);
}
