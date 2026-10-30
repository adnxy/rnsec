module.exports = ({ config }) => ({
  expo: {
    // runtimeVersion alone, with a spread that may supply updates.codeSigning*
    runtimeVersion: '1.0.0',
    android: { permissions: ['android.permission.CAMERA'], ...config.android },
    updates: { url: 'http://updates.example.test/manifest' },
    ...config,
  },
});
