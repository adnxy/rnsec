import CryptoJS from 'crypto-js';

const encryptionKey = process.env.PAYLOAD_ENCRYPTION_KEY ?? '';

export function encryptPayload(payload: string): string {
  return CryptoJS.AES.encrypt(payload, encryptionKey).toString();
}
