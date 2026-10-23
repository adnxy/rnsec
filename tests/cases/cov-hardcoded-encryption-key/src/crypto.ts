import CryptoJS from 'crypto-js';

const encryptionKey = '3f9a1c7e5b2d48a6908e1d7c4b6a2f13';

export function encryptPayload(payload: string): string {
  return CryptoJS.AES.encrypt(payload, encryptionKey).toString();
}
