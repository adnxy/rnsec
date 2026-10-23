import jwt from 'jsonwebtoken';
import { SignJWT } from 'jose';

export const a = jwt.sign({ id: 1 }, process.env.JWT_SECRET);
export const b = jwt.sign({ id: 1 }, secret);
export const c = jwt.sign({ id: 1 }, '');
export const d = jwt.sign({ id: 1 }, '<your-secret>');
export const e = jwt.verify('t', key, { algorithms: ['RS256'] });
export const f = new SignJWT({}).sign(new TextEncoder().encode(process.env.KEY));
