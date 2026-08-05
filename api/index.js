// -----------------------------------------------------------------------------
// Vercel serverless entry point
// -----------------------------------------------------------------------------
const crypto = require('crypto');
const { applyCorsHeaders } = require('../cors-config');

let app;

function requestPath(req) {
  try {
    return new URL(req.url || '/', 'http://localhost').pathname.replace(/\/+$/, '') || '/';
  } catch (_) {
    return req.url || '/';
  }
}

function sendJson(res, statusCode, payload) {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
}

function startupErrorCode(error) {
  const message = String(error?.message || error || '');
  if (/MONGO_URI is required/i.test(message)) return 'MISSING_MONGO_URI';
  if (/JWT_SECRET/i.test(message)) return 'INVALID_JWT_SECRET';
  if (/Email notifications are enabled|RESENDER_API_KEY|SENDING_EMAIL/i.test(message)) return 'EMAIL_CONFIGURATION_ERROR';
  if (/Production configuration blocked|Real-money mode blocked/i.test(message)) return 'PRODUCTION_CONFIGURATION_BLOCKED';
  if (/server selection|ECONNREFUSED|querySrv|ENOTFOUND|authentication failed/i.test(message)) return 'DATABASE_UNAVAILABLE';
  return 'STARTUP_FAILED';
}

module.exports = async (req, res) => {
  const requestId = req.headers['x-request-id'] || crypto.randomUUID();
  res.setHeader('X-Request-ID', requestId);

  // Handle CORS before database/configuration startup. Otherwise a startup 503
  // has no CORS headers and browsers misleadingly report it as a CORS failure.
  if (!applyCorsHeaders(req, res)) {
    return sendJson(res, 403, {
      success: false,
      message: 'Origin is not allowed by CORS.',
      errors: [],
    });
  }

  // A preflight request must not depend on MongoDB being reachable.
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  try {
    // Lazy loading lets this handler return a useful, CORS-enabled response
    // even when module-level configuration (for example email settings) fails.
    if (!app) app = require('../server');

    // Liveness should remain available even when MongoDB is temporarily down.
    const pathname = requestPath(req);
    if (pathname === '/api/health' || pathname === '/health') {
      return app(req, res);
    }

    await app.prepareRuntime();
    return app(req, res);
  } catch (error) {
    const errorCode = startupErrorCode(error);
    console.error('Startup failed:', errorCode, error?.message || error);
    res.setHeader('X-Startup-Error-Code', errorCode);
    return sendJson(res, 503, {
      success: false,
      message: 'Service is temporarily unavailable. Please try again shortly.',
      errors: [],
    });
  }
};

module.exports.config = {
  api: {
    bodyParser: false,
  },
};
