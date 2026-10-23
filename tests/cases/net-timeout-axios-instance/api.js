import axios from 'axios';
axios.defaults.timeout = 8000;
export function call() {
  return axios.get('https://api.example.com/a', { headers: {} });
}
