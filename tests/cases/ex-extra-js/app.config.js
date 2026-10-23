module.exports = ({ config }) => ({
  ...config,
  name: 'demo',
  extra: {
    apiBase: 'https://api.example-corp.com',
    sessionSecret: 'fake-session-value-1',
    envSecret: process.env.API_SECRET,
    placeholderSecret: 'changeme',
  },
});
