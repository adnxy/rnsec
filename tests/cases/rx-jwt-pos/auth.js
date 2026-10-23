import jwt from 'jsonwebtoken';
import { SignJWT, jwtVerify } from 'jose';

export const a = jwt.sign({ id: 1 }, 'fake-demo-signing-value');
export const b = jwt.verify('t', 'fake-demo-signing-value');
export const c = new SignJWT({ id: 1 }).setProtectedHeader({ alg: 'HS256' }).sign(new TextEncoder().encode('fake-demo-key-value'));
export const d = jwt.verify('t', key, { algorithms: ['none'] });
export const e = { secretOrKey: 'fake-demo-passport-value' };
