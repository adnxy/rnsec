const config = {
  stripeKey: '{{fake:stripe_live}}',
};
export function load() {
  if (__DEV__) {
    // dev-only: allowed
    fetch('http://dev-server.example-corp.com/debug');
  } else {
    fetch('http://prod-server.example-corp.com/data');
  }
}
if (__DEV__ && false) {}
