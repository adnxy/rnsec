import type { ConfigContext, ExpoConfig } from 'expo/config';

const updatesUrl = process.env.UPDATES_URL;
const updatesConfig = { url: 'http://updates.example.test/manifest' };
const permissions = ['android.permission.CAMERA'];

// Nothing here can be established statically, so nothing is reported:
// the permission list and `updates` come from variables, and a literal http:// url
// that is not under expo.updates is not an updates url
export default ({ config }: ConfigContext): ExpoConfig => ({
  ...config,
  name: 'demo',
  slug: 'demo',
  runtimeVersion: '1.0.0',
  android: { permissions },
  updates: updatesConfig,
  extra: {
    legacy: { updates: { url: 'http://old.example.test/manifest' }, url: updatesUrl },
  },
});
