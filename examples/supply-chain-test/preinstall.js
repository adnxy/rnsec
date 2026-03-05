// Test fixture: triggers OBFUSCATED_EVAL_EXECUTION (do not run - for rnsec tests only)
const s = (v) => [...v].map((w) => w.codePointAt(0)).filter((n) => n !== undefined);
eval(Buffer.from(s('dummy')).toString('utf-8'));
