// Static literals that are fine: https url, signed updates, harmless permissions
module.exports = {
  expo: {
    name: 'demo',
    slug: 'demo',
    runtimeVersion: '1.0.0',
    updates: {
      url: 'https://u.expo.dev/00000000-0000-0000-0000-000000000000',
      codeSigningCertificate: './code-signing/certificate.pem',
      codeSigningMetadata: { keyid: 'main', alg: 'rsa-v1_5-sha256' },
    },
    android: {
      permissions: ['android.permission.VIBRATE', 'android.permission.INTERNET'],
    },
  },
};
