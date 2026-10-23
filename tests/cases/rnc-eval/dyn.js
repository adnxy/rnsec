module.exports = function run(code) {
  eval(code);
  return new Function(code)();
};
