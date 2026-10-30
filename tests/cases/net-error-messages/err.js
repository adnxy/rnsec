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
export function toastShow(fetchUser) {
  fetchUser().catch(e => {
    Toast.show({ type: 'error', text1: e.message });
  });
}
export function promiseAlert(fetchUser) {
  fetchUser().catch(failure => Alert.alert('Failed', failure.message));
}
export function serverReply(res, err) {
  res.status(500).json({ error: err.stack });
}
export function logHeaders(error) {
  console.error('request failed', error.config.headers);
}
export function logToken(error) {
  console.warn(error.token);
}
export function logCode(error) {
  console.error(error.code, error.status);
  console.warn('failed', error);
  console.error(error.message);
}
export function constantToast() {
  Toast.show({ type: 'error', text1: 'Could not load' });
  res.status(500).json({ error: 'Internal error' });
}
export function validationToasts(errors) {
  errors.map(error => {
    Toast.show(error, { type: 'warning' });
  });
}
export function bareCaught(load) {
  load().catch(failure => Toast.show(failure));
}
