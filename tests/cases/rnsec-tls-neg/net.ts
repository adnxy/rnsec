import https from 'https';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
  throw new Error('TLS validation must stay enabled');
}
export const agent = new https.Agent({ keepAlive: true });
agent.options.rejectUnauthorized = true;
