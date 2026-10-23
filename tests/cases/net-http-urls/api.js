import axios from 'axios';

const host = 'x';
const port = 3000;
export async function localCalls(timeout) {
  await fetch('http://localhost:3000/api', { timeout });
  await fetch('http://10.0.2.2:8080/emulator', { timeout });
  await fetch('http://127.0.0.1/loop', { timeout });
  await fetch('http://[::1]:3000/v6', { timeout });
  await fetch('http://dev-box.local/x', { timeout });
  await fetch('http://192.168.1.5/lan', { timeout });
  await fetch('http://172.20.0.1/docker', { timeout });
  await fetch(`http://localhost:${port}/tpl`, { timeout });
  await fetch(`http://${host}/unknown-host`, { timeout });
  await axios.get('http://10.1.2.3/axios', { timeout });
  return axios.create({ baseURL: 'http://localhost:8080', timeout });
}
export async function publicCalls(id, timeout) {
  await fetch('http://api.example.com/plain', { timeout });
  await fetch('http://110.0.0.1/not-private', { timeout });
  await fetch('http://notlocalhost.example.com/x', { timeout });
  await fetch('http://172.32.0.1/outside-172-16-31', { timeout });
  await fetch(`http://tpl.example.com/users/${id}`, { timeout });
  await axios.get('http://axios.example.com/data', { timeout });
  return axios.create({ baseURL: 'http://base.example.com/v1/' + id, timeout });
}
