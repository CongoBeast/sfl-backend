// -----------------------------------------------------------------------------
// Vercel serverless entry point
// -----------------------------------------------------------------------------
// `server.js` (project root) is the original, unmodified Express app: every
// route, model, and piece of business logic lives there exactly as it did
// for traditional Node hosting. Nothing about how the API responds to the
// frontend changes.
//
// This file only adapts that app to run as a single Vercel serverless
// function:
//
// 1. Vercel's Node.js runtime parses the request body itself by default,
//    which would consume the stream before Express's own body parsers
//    (express.json() / express.urlencoded()) get a chance to read it. The
//    `config.api.bodyParser = false` export below turns that off so the
//    app's existing middleware keeps working unchanged.
//
// 2. There is no long-running `app.listen()` on Vercel, so the one-time
//    startup work that normally happens inside `start()` (connecting to
//    MongoDB, seeding demo data, running startup backfills) never runs on
//    its own. This handler awaits `prepareRuntime()` before passing the
//    request to the app. `prepareRuntime()` caches its promise on
//    `global`, so this only does real work on a cold start — warm
//    invocations resolve instantly.
const app = require('../server');

module.exports = async (req, res) => {
  try {
    await app.prepareRuntime();
  } catch (error) {
    console.error('Startup failed:', error.message);
    res.statusCode = 503;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      success: false,
      message: 'Service is temporarily unavailable. Please try again shortly.',
      errors: [],
    }));
    return;
  }

  return app(req, res);
};

module.exports.config = {
  api: {
    bodyParser: false,
  },
};
