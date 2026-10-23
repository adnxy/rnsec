export const safe = [
  '/api/debug-utils/list',
  'https://api.example.com/debuggers/x',
  'http://localhost:3000/debug/info',
  'http://10.0.2.2:8080/debug/info',
  'https://api.example.com/api/debugger',
];
export const exposed = [
  'https://api.example.com/debug/info',
  'https://api.example.com/api/debug',
  'https://api.example.com/admin/debug',
  'https://api.example.com/__debug__/toolbar',
  'https://api.example.com/v110.0.1/debug/trace',
];
