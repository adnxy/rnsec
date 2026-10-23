export const a = 'https://deploy:fakepw42@api.example-corp.com/v1';
export const b = `postgres://svc:fakepw42@db.example-corp.com:5432/app`;
export const c = btoa('svcuser:fakepw42');
export const d = Buffer.from('svcuser:fakepw42').toString('base64');
export const e = { Authorization: 'Basic c3ZjdXNlcjpmYWtlcHc0Mg==' };
export const f = 'http://admin:admin@localhost:8080/x';
