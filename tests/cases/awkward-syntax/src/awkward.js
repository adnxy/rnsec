const crypto = require('crypto');
const key = { 0: 'k', 1: 'e', [Date.now()]: Math.random(), ...{ 2: 'y' } };
module.exports = {
  1: function encrypt(x) { return crypto.createHash('md5').update(`${x}${key[0]}`).digest('hex'); },
  async *[Symbol.asyncIterator]() { yield key?.[1]; },
  'a-b': { c: { 3: new Function('return 1') } },
  token: `${Math.random()}`.slice(2),
};
label: for (const i in key) { if (i) continue label; }
