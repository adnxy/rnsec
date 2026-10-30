module.exports = ({ config }) => ({
  ...config,
  name: 'demo',
  updates: {
    url: 'http://updates.example.test/manifest',
    enabled: true,
  },
  android: {
    permissions: ['android.permission.RECORD_AUDIO'],
  },
});
