const a = eval("1+1");
const b = new Function("return 2")();
const c = Function("return 3")();
module.exports = { a, b, c };
