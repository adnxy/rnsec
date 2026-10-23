import tls from 'tls';
import https from 'https';
import constants from 'constants';

// ciphers: 'RC4-SHA', minVersion: 'TLSv1.1' in comment; DESCRIPTION cipher
export const DESCRIPTION = 'a cipher description';
export const opts = {
  secureOptions: constants.SSL_OP_NO_TLSv1 | constants.SSL_OP_NO_TLSv1_1,
  ciphers: '!RC4:!DES:!MD5:!aNULL:ECDHE-RSA-AES128-GCM-SHA256',
  minVersion: 'TLSv1.2',
};
export const weakProto = { minVersion: 'TLSv1.1' };
export const weakCipher = { ciphers: 'RC4-SHA:AES128-SHA' };
export const suite = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA';
export const agent = new https.Agent({ rejectUnauthorized: false });
export const cfg = { httpsAgent: agent };
export { tls };
