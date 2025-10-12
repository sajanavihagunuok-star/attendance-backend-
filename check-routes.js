const routes = ['me','students','courses','sessions','users','institutes','academic_years','auth','attendance','admin'];
const path = require('path');
routes.forEach(r => {
  try {
    console.log(r, '->', require.resolve(path.join(__dirname, 'routes', r)));
  } catch (e) {
    console.error(r, 'resolve error:', e.message);
  }
});