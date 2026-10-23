import https from 'https';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const agent = new https.Agent({});
agent.options.rejectUnauthorized = false;
export const lax = new https.Agent({ rejectUnauthorized: false });
export { agent };
