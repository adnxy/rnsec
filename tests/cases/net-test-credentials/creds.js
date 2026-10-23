const bypass = 'admin';
const passport = 'test';
const isBypassAuth = 'demo';
const password = '';
const emptyPass = '';
const dynamic = { password: process.env.PW, username: getName() };
const roles = { userRole: 'admin', administrator: 'x', password: 'administrator-secret' };
// password = 'admin' in a comment is not code
function getName() { return 'x'; }
export { bypass, passport, isBypassAuth, password, emptyPass, dynamic, roles };
