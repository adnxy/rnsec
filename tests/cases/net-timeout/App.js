import axios from 'axios';

export async function plain() {
  return fetch('https://api.example.com/plain');
}
export async function withSignal() {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 5000);
  const res = await fetch('https://api.example.com/abort');
  clearTimeout(t);
  return res;
}
export async function withAbortSignalTimeout() {
  return fetch('https://api.example.com/sigtimeout', { signal: AbortSignal.timeout(5000) });
}
export async function withRace() {
  const timer = new Promise((_, rej) => setTimeout(rej, 3000));
  return Promise.race([fetch('https://api.example.com/race'), timer]);
}
export async function opts() {
  return fetch('https://api.example.com/opts', { method: 'POST' });
}
export async function axiosNoTimeout() {
  return axios.get('https://api.example.com/a', { headers: {} });
}
export async function axiosTimeout() {
  return axios.get('https://api.example.com/b', { timeout: 5000, headers: {} });
}
