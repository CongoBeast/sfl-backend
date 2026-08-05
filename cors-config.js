'use strict';

function normalizeOrigin(value = '') {
  return String(value).trim().replace(/\/+$/, '');
}

const CLIENT_ORIGIN = normalizeOrigin(process.env.CLIENT_ORIGIN || 'http://localhost:3000');
const CLIENT_ORIGINS = [...new Set([
  CLIENT_ORIGIN,
  ...String(process.env.CLIENT_ORIGINS || '').split(',').map(normalizeOrigin),
].filter(Boolean))];

function isAllowedOrigin(origin) {
  if (!origin) return true;
  return CLIENT_ORIGINS.includes(normalizeOrigin(origin));
}

function appendVary(res, value) {
  const current = res.getHeader('Vary');
  if (!current) {
    res.setHeader('Vary', value);
    return;
  }

  const values = String(current).split(',').map((item) => item.trim().toLowerCase());
  if (!values.includes(String(value).toLowerCase())) {
    res.setHeader('Vary', `${current}, ${value}`);
  }
}

function applyCorsHeaders(req, res) {
  const origin = req.headers?.origin;
  if (!origin) return true;
  if (!isAllowedOrigin(origin)) return false;

  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  appendVary(res, 'Origin');

  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      req.headers['access-control-request-headers'] || 'Authorization,Content-Type,X-Requested-With,X-Request-ID'
    );
    res.setHeader('Access-Control-Max-Age', '86400');
  }

  return true;
}

module.exports = {
  CLIENT_ORIGIN,
  CLIENT_ORIGINS,
  normalizeOrigin,
  isAllowedOrigin,
  applyCorsHeaders,
};
