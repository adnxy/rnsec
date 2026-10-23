import { io } from 'socket.io-client';
export const a = new WebSocket('wss://chat.example-corp.com/socket');
export const b = new WebSocket('ws://localhost:8081');
export const c = new WebSocket('ws://10.0.2.2:8081/x');
export const d = new WebSocket(`ws://${host}/x`);
export const e = io('wss://chat.example-corp.com');
export const f = new WebSocket(url);
export const g = new WebSocket('ws://192.168.1.20:3000');
