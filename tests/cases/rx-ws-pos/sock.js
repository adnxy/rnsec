import { io } from 'socket.io-client';
export const a = new WebSocket('ws://chat.example-corp.com/socket');
export const b = io('ws://chat.example-corp.com');
export const c = new WebSocket(`ws://chat.example-corp.com:${port}/live`);
