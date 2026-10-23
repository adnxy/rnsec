export const run = (client: any, v: string) => client.execute(`SELECT 1 FROM t WHERE a = ${v}`);
