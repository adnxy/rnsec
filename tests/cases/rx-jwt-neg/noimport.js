const jwt = { sign: (a, b) => a + b };
export const a = jwt.sign({ id: 1 }, 'fake-demo-signing-value');
export const o = { secretOrKey: 'fake-demo-passport-value', algorithms: ['none'] };
