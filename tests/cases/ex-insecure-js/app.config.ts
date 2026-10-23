import type { ExpoConfig } from 'expo/config';

const config: ExpoConfig = {
  name: 'demo',
  slug: 'demo',
  android: {
    allowBackup: true,
  },
  ios: {
    infoPlist: {
      NSAppTransportSecurity: { NSAllowsArbitraryLoads: true },
    },
  },
  plugins: [['expo-build-properties', { android: { usesCleartextTraffic: true } }]],
};

export default config;
