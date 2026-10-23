declare const flag: boolean;

export const STRIPE_KEY = __DEV__ ? 'sk_test_51Nq7XaB3cD9eF2gH5iJ8kL1mN4oP7qR0' : '{{fake:stripe_live}}';

export function a() {
  if (!__DEV__ && flag) {
    fetch('http://one.example-corp.com/x');
  } else {
    fetch('http://two.example-corp.com/x');
  }
}

export function b() {
  if (__DEV__ && flag) fetch('http://three.example-corp.com/x');
  __DEV__ && fetch('http://four.example-corp.com/x');
  process.env.NODE_ENV === 'production' || fetch('http://five.example-corp.com/x');
  if (__DEV__) fetch('http://six.example-corp.com/x');
}
