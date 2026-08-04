const app = require('../server.local');

module.exports = async function supremeFantasyLeagueHandler(req, res) {
  try {
    await app.prepareRuntime();
    return app(req, res);
  } catch (error) {
    console.error('Vercel function initialization failed:', error);
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({
        success: false,
        message: 'The service could not initialize. Please try again shortly.',
      }));
    }
    return undefined;
  }
};
