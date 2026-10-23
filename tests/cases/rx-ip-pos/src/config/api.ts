export const config = {
  apiUrl: 'https://45.33.32.156/v1',
  host: '45.33.32.156',
};
export const socket = new WebSocket('ws://45.33.32.156:9000/live');
export const legacy = fetch('http://45.33.32.156:8080/api');
