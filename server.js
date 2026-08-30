const path = require('path');
// Environment files are loaded for self-hosted deployments; managed platforms may provide variables directly.
require('dotenv').config({ path: path.join(__dirname, '.env.local') });
require('dotenv').config({ path: path.join(__dirname, '.env') });

const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT || 8000);
const COOKIE_NAME = process.env.COOKIE_NAME || 'sfl_session';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const { CLIENT_ORIGIN, CLIENT_ORIGINS, isAllowedOrigin } = require('./cors-config');
const IS_PRODUCTION = String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
const IS_VERCEL = Boolean(process.env.VERCEL);
const PAYMENTS_MODE = String(process.env.PAYMENTS_MODE || 'mock').trim().toLowerCase();
const MOCK_PAYMENTS = PAYMENTS_MODE === 'mock';
const PAYNOW_PAYMENTS = PAYMENTS_MODE === 'paynow';
const PAYNOW_TEST_MODE = String(process.env.PAYNOW_TEST_MODE || 'true').trim().toLowerCase() !== 'false';
const PAYNOW_TEST_AUTH_EMAIL = String(process.env.PAYNOW_TEST_AUTH_EMAIL || '').trim().toLowerCase();
const PAYNOW_INTEGRATION_ID = String(process.env.PAYNOW_INTEGRATION_ID || '').trim();
const PAYNOW_INTEGRATION_KEY = String(process.env.PAYNOW_INTEGRATION_KEY || '').trim();
const PUBLIC_API_URL = String(process.env.PUBLIC_API_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const PAYNOW_RESULT_URL = String(process.env.PAYNOW_RESULT_URL || `${PUBLIC_API_URL}/api/payments/paynow/result`).trim();
const PAYNOW_RETURN_URL = String(process.env.PAYNOW_RETURN_URL || `${CLIENT_ORIGIN}/app/subscription`).trim();
const PAYNOW_REQUEST_TIMEOUT_MS = Math.max(5000, Math.min(45000, Number(process.env.PAYNOW_REQUEST_TIMEOUT_MS || 15000)));
const PAYNOW_PENDING_RECONCILE_INTERVAL_MS = Math.max(60000, Number(process.env.PAYNOW_PENDING_RECONCILE_INTERVAL_MS || 300000));
const SUBSCRIPTION_CHECK_INTERVAL_MS = Math.max(60000, Number(process.env.SUBSCRIPTION_CHECK_INTERVAL_MS || 900000));
const SUBSCRIPTION_WALLET_SEED_CENTS = Math.max(0, Math.round(Number(process.env.SUBSCRIPTION_WALLET_SEED_CENTS || 0)));
const FPL_DATA_MODE = String(process.env.FPL_DATA_MODE || 'mock').trim().toLowerCase();
const MOCK_FANTASY = FPL_DATA_MODE === 'mock';
const FPL_BASE_URL = String(process.env.FPL_BASE_URL || 'https://fantasy.premierleague.com/api').replace(/\/$/, '');
const FPL_CACHE_MINUTES = Math.max(1, Math.min(60, Number(process.env.FPL_CACHE_MINUTES || 10)));
const FPL_REQUEST_TIMEOUT_MS = Math.max(3000, Math.min(30000, Number(process.env.FPL_REQUEST_TIMEOUT_MS || 12000)));
const FPL_LEAGUE_SCORE_CACHE_MINUTES = Math.max(1, Math.min(60, Number(process.env.FPL_LEAGUE_SCORE_CACHE_MINUTES || 2)));
const FPL_PAGE_REFRESH_CACHE_MINUTES = Math.max(1, Math.min(30, Number(process.env.FPL_PAGE_REFRESH_CACHE_MINUTES || 10)));
const SUPREME_PLANNING_HORIZON_DAYS = Math.max(30, Math.min(120, Number(process.env.SUPREME_PLANNING_HORIZON_DAYS || 60)));
const FPL_LEAGUE_SYNC_INTERVAL_MS = Math.max(60000, Number(process.env.FPL_LEAGUE_SYNC_INTERVAL_MS || 900000));
const FPL_LEAGUE_SYNC_LIMIT = Math.max(1, Math.min(50, Number(process.env.FPL_LEAGUE_SYNC_LIMIT || 10)));
// Bounds how many members' full squads (picks, captain, bench, etc.) get refreshed
// per daily maintenance run. This is separate from FPL_LEAGUE_SYNC_LIMIT, which only
// refreshes aggregate league scores and is much cheaper per member.
const FPL_TEAM_SNAPSHOT_SYNC_LIMIT = Math.max(1, Math.min(5000, Number(process.env.FPL_TEAM_SNAPSHOT_SYNC_LIMIT || 1000)));
const SEED_DEMO_DATA = String(process.env.SEED_DEMO_DATA || (IS_PRODUCTION ? 'false' : 'true')).trim().toLowerCase() === 'true';
const CLOUDINARY_CLOUD_NAME = String(process.env.CLOUDINARY_CLOUD_NAME || '').trim();
const CLOUDINARY_API_KEY = String(process.env.CLOUDINARY_API_KEY || '').trim();
const CLOUDINARY_API_SECRET = String(process.env.CLOUDINARY_API_SECRET || '').trim();
const CLOUDINARY_UPLOAD_PRESET = String(process.env.CLOUDINARY_UPLOAD_PRESET || '').trim();
const CLOUDINARY_PROFILE_FOLDER = String(process.env.CLOUDINARY_PROFILE_FOLDER || 'supreme-fantasy-league/profile-pictures')
  .trim()
  .replace(/^\/+|\/+$/g, '');
const CLOUDINARY_REQUEST_TIMEOUT_MS = Math.max(5000, Math.min(45000, Number(process.env.CLOUDINARY_REQUEST_TIMEOUT_MS || 15000)));
const PROFILE_IMAGE_MAX_BYTES = Math.max(256 * 1024, Math.min(5 * 1024 * 1024, Number(process.env.PROFILE_IMAGE_MAX_BYTES || 2 * 1024 * 1024)));
const LEGAL_TERMS_VERSION = String(process.env.LEGAL_TERMS_VERSION || '1.0').trim();
const LEGAL_PRIVACY_VERSION = String(process.env.LEGAL_PRIVACY_VERSION || '1.0').trim();
const LEGAL_RULES_VERSION = String(process.env.LEGAL_RULES_VERSION || '1.0').trim();
const LEGAL_EFFECTIVE_DATE = String(process.env.LEGAL_EFFECTIVE_DATE || '2026-08-03').trim();
const ADMIN_NOTIFICATION_EMAIL = String(process.env.ADMIN_NOTIFICATION_EMAIL || '').trim().toLowerCase();
mongoose.set('autoIndex', String(process.env.MONGOOSE_AUTO_INDEX || (IS_PRODUCTION ? 'false' : 'true')).trim().toLowerCase() === 'true');

// -----------------------------------------------------------------------------
// Runtime safety gates
// -----------------------------------------------------------------------------
function assertProductionSafetyGates() {
  if (PAYNOW_PAYMENTS && !PAYNOW_TEST_MODE && process.env.REAL_MONEY_ENABLED !== 'true') {
    throw new Error('Live Paynow checkout requires REAL_MONEY_ENABLED=true and all production approval gates.');
  }
  if (process.env.REAL_MONEY_ENABLED !== 'true') return;
  const required = [
    'LEGAL_APPROVAL_CONFIRMED',
    'FANTASY_DATA_AUTHORIZED',
    'PAYMENT_PROVIDER_APPROVED',
  ];
  const missing = required.filter((key) => process.env[key] !== 'true');
  if (missing.length) {
    throw new Error(`Real-money mode blocked. Required deployment safeguards are not enabled: ${missing.join(', ')}`);
  }
}
assertProductionSafetyGates();

// -----------------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------------
const money = (value) => Math.round(Number(value || 0));
const createReference = (prefix) => `${prefix}-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
const normalizeEmail = (email = '') => String(email).trim().toLowerCase();
const normalizeInviteCode = (value = '') => String(value)
  .trim()
  .toUpperCase()
  .replace(/[^A-Z0-9-]/g, '')
  .replace(/-+/g, '-')
  .replace(/^-|-$/g, '');
const isValidInviteCode = (value) => /^[A-Z0-9][A-Z0-9-]{4,14}[A-Z0-9]$/.test(value);
const clamp = (n, min, max) => Math.max(min, Math.min(max, n));
const isAdult = (dateOfBirth) => {
  const dob = new Date(dateOfBirth);
  if (Number.isNaN(dob.getTime())) return false;
  const cutoff = new Date();
  cutoff.setFullYear(cutoff.getFullYear() - 18);
  return dob <= cutoff;
};
const userHasCurrentLegalAcceptance = (user) => Boolean(
  user?.legalAcceptance?.acceptedAt
  && user.legalAcceptance?.termsVersion === LEGAL_TERMS_VERSION
  && user.legalAcceptance?.privacyVersion === LEGAL_PRIVACY_VERSION
  && user.legalAcceptance?.rulesVersion === LEGAL_RULES_VERSION
);
const publicUser = (user, profile = null) => ({
  id: user._id,
  fullName: user.fullName,
  email: user.email,
  phone: user.phone,
  dateOfBirth: user.dateOfBirth,
  role: user.role,
  country: user.country,
  currency: user.currency,
  status: user.status,
  fplManagerId: user.fplManagerId,
  fantasyTeamName: user.fantasyTeamName,
  profilePicture: profile?.profilePicture || '',
  legalAcceptanceRequired: user.role === 'user' && !userHasCurrentLegalAcceptance(user),
  legalVersions: {
    terms: LEGAL_TERMS_VERSION,
    privacy: LEGAL_PRIVACY_VERSION,
    rules: LEGAL_RULES_VERSION,
    effectiveDate: LEGAL_EFFECTIVE_DATE,
  },
});
const success = (res, data = {}, status = 200) => res.status(status).json({ success: true, data });
const failure = (res, status, message, errors = []) => res.status(status).json({ success: false, message, errors });

const PROFILE_IMAGE_TYPES = Object.freeze({
  'image/jpeg': { extension: 'jpg' },
  'image/png': { extension: 'png' },
  'image/webp': { extension: 'webp' },
});

function cloudinarySignedConfigured() {
  return Boolean(CLOUDINARY_CLOUD_NAME && CLOUDINARY_API_KEY && CLOUDINARY_API_SECRET);
}

function cloudinaryUnsignedConfigured() {
  return Boolean(CLOUDINARY_CLOUD_NAME && CLOUDINARY_UPLOAD_PRESET);
}

function cloudinaryConfigured() {
  return cloudinarySignedConfigured() || cloudinaryUnsignedConfigured();
}

function imageSignatureMatches(buffer, mimeType) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return false;
  if (mimeType === 'image/jpeg') {
    return buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  }
  if (mimeType === 'image/png') {
    return buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  }
  if (mimeType === 'image/webp') {
    return buffer.subarray(0, 4).toString('ascii') === 'RIFF'
      && buffer.subarray(8, 12).toString('ascii') === 'WEBP';
  }
  return false;
}

function parseProfileImageDataUrl(dataUrl) {
  if (typeof dataUrl !== 'string') {
    return { ok: false, message: 'Select a PNG, JPEG, or WebP image.' };
  }

  const match = dataUrl.match(/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=\r\n]+)$/i);
  if (!match) {
    return { ok: false, message: 'Only PNG, JPEG, and WebP images can be uploaded.' };
  }

  const mimeType = match[1].toLowerCase();
  const base64 = match[2].replace(/\s/g, '');
  if (!PROFILE_IMAGE_TYPES[mimeType] || !base64 || base64.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
    return { ok: false, message: 'The selected file is not a valid renderable image.' };
  }

  let buffer;
  try {
    buffer = Buffer.from(base64, 'base64');
  } catch {
    return { ok: false, message: 'The selected image could not be decoded.' };
  }

  if (!buffer.length || buffer.length > PROFILE_IMAGE_MAX_BYTES) {
    return {
      ok: false,
      message: `Profile pictures must be ${Math.round(PROFILE_IMAGE_MAX_BYTES / (1024 * 1024))} MB or smaller.`,
    };
  }

  if (!imageSignatureMatches(buffer, mimeType)) {
    return {
      ok: false,
      message: 'The file extension and contents do not match a supported image format.',
    };
  }

  return {
    ok: true,
    buffer,
    mimeType,
    extension: PROFILE_IMAGE_TYPES[mimeType].extension,
  };
}

function cloudinarySignature(parameters) {
  const signingString = Object.keys(parameters)
    .sort()
    .map((key) => `${key}=${parameters[key]}`)
    .join('&');
  return crypto.createHash('sha1').update(`${signingString}${CLOUDINARY_API_SECRET}`).digest('hex');
}

async function cloudinaryRequest(action, parameters, file = null) {
  if (!cloudinarySignedConfigured()) {
    const error = new Error('Signed Cloudinary operations are not configured. Add CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET, then restart the backend.');
    error.status = 503;
    throw error;
  }
  if (typeof fetch !== 'function' || typeof FormData !== 'function' || typeof Blob !== 'function') {
    const error = new Error('This Node.js runtime does not support secure image uploads. Use Node.js 18 or newer.');
    error.status = 500;
    throw error;
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const signedParameters = { ...parameters, timestamp: String(timestamp) };
  const form = new FormData();
  Object.entries(signedParameters).forEach(([key, value]) => form.append(key, String(value)));
  form.append('api_key', CLOUDINARY_API_KEY);
  form.append('signature', cloudinarySignature(signedParameters));

  if (file) {
    form.append('file', new Blob([file.buffer], { type: file.mimeType }), `profile.${file.extension}`);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CLOUDINARY_REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(
      `https://api.cloudinary.com/v1_1/${encodeURIComponent(CLOUDINARY_CLOUD_NAME)}/image/${action}`,
      { method: 'POST', body: form, signal: controller.signal }
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.error) {
      const error = new Error(payload?.error?.message || `Cloudinary returned HTTP ${response.status}.`);
      error.status = response.status === 401 || response.status === 403 ? 503 : 502;
      error.cloudinaryHttpStatus = response.status;
      throw error;
    }
    return payload;
  } catch (error) {
    if (error.name === 'AbortError') {
      const timeoutError = new Error('Cloudinary did not respond before the upload timed out. Please try again.');
      timeoutError.status = 504;
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function cloudinaryUnsignedUpload(userId, image) {
  if (!cloudinaryUnsignedConfigured()) {
    const error = new Error('Cloudinary upload permission is missing and no unsigned upload preset is configured.');
    error.status = 503;
    throw error;
  }
  if (typeof fetch !== 'function' || typeof FormData !== 'function' || typeof Blob !== 'function') {
    const error = new Error('This Node.js runtime does not support secure image uploads. Use Node.js 18 or newer.');
    error.status = 500;
    throw error;
  }

  const form = new FormData();
  form.append('upload_preset', CLOUDINARY_UPLOAD_PRESET);
  if (CLOUDINARY_PROFILE_FOLDER) form.append('folder', CLOUDINARY_PROFILE_FOLDER);
  form.append('context', `sfl_user_id=${String(userId)}`);
  form.append('file', new Blob([image.buffer], { type: image.mimeType }), `profile.${image.extension}`);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CLOUDINARY_REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(
      `https://api.cloudinary.com/v1_1/${encodeURIComponent(CLOUDINARY_CLOUD_NAME)}/image/upload`,
      { method: 'POST', body: form, signal: controller.signal }
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.error) {
      const error = new Error(payload?.error?.message || `Cloudinary returned HTTP ${response.status}.`);
      error.status = response.status === 401 || response.status === 403 ? 503 : 502;
      error.cloudinaryHttpStatus = response.status;
      throw error;
    }
    return payload;
  } catch (error) {
    if (error.name === 'AbortError') {
      const timeoutError = new Error('Cloudinary did not respond before the upload timed out. Please try again.');
      timeoutError.status = 504;
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function uploadProfilePictureToCloudinary(userId, image) {
  if (cloudinarySignedConfigured()) {
    const publicId = `user-${String(userId)}`;
    try {
      return await cloudinaryRequest('upload', {
        folder: CLOUDINARY_PROFILE_FOLDER,
        invalidate: 'true',
        overwrite: 'true',
        public_id: publicId,
        unique_filename: 'false',
        use_filename: 'false',
      }, image);
    } catch (error) {
      const permissionDenied = error.cloudinaryHttpStatus === 403
        || /missing permissions|actions=\[?['"]?create/i.test(String(error.message || ''));
      if (!permissionDenied || !cloudinaryUnsignedConfigured()) throw error;
      console.warn('Signed Cloudinary key cannot create assets; using configured unsigned upload preset.');
    }
  }
  return cloudinaryUnsignedUpload(userId, image);
}

async function removeProfilePictureFromCloudinary(publicId) {
  if (!publicId) return { result: 'not found' };
  if (!cloudinarySignedConfigured()) return { result: 'skipped-no-signed-credentials' };
  return cloudinaryRequest('destroy', {
    invalidate: 'true',
    public_id: publicId,
  });
}

function cloudinaryPublicErrorMessage(error) {
  let reason = String(error?.message || 'Unknown Cloudinary error.');
  if (/missing permissions|actions=\[?['"]?create/i.test(reason)) {
    return 'The configured Cloudinary API key is restricted and cannot create image assets. In Cloudinary, use an API key with Upload/Create permission, or create an unsigned upload preset and set CLOUDINARY_UPLOAD_PRESET on the server. Restart the backend after changing the environment.';
  }
  if (CLOUDINARY_API_SECRET) reason = reason.split(CLOUDINARY_API_SECRET).join('[redacted]');
  if (CLOUDINARY_API_KEY) reason = reason.split(CLOUDINARY_API_KEY).join('[redacted]');
  return reason;
}



const walletIdentifierFor = (userId) => `SFLW-${String(userId).toUpperCase()}`;
const normalizeZimbabwePhone = (value = '') => {
  const digits = String(value).replace(/\D/g, '');
  if (/^263\d{9}$/.test(digits)) return `+${digits}`;
  if (/^0\d{9}$/.test(digits)) return `+263${digits.slice(1)}`;
  if (/^\d{9}$/.test(digits)) return `+263${digits}`;
  return '';
};
const normalizePaynowStatus = (value = '') => String(value).trim().toLowerCase().replace(/\s+/g, ' ');
const paynowStatusIsPaid = (value) => ['paid', 'awaiting delivery', 'delivered'].includes(normalizePaynowStatus(value));
const paynowStatusIsTerminalFailure = (value) => ['cancelled', 'failed', 'error', 'invalid id'].includes(normalizePaynowStatus(value));
const paynowStatusIsRefunded = (value) => normalizePaynowStatus(value) === 'refunded';

// -----------------------------------------------------------------------------
// Mongoose schemas and models — intentionally kept in this single backend file
// -----------------------------------------------------------------------------
const { Schema } = mongoose;

const userSchema = new Schema({
  fullName: { type: String, required: true, trim: true, maxlength: 120 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
  phone: { type: String, required: true, trim: true },
  dateOfBirth: { type: Date, required: true },
  passwordHash: { type: String, required: true, select: false },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  country: { type: String, default: 'Zimbabwe' },
  currency: { type: String, default: 'USD' },
  ageConfirmed: { type: Boolean, required: true },
  legalAcceptance: {
    termsVersion: { type: String, default: '' },
    privacyVersion: { type: String, default: '' },
    rulesVersion: { type: String, default: '' },
    effectiveDate: { type: String, default: '' },
    acceptedAt: { type: Date, default: null },
    securityAcknowledgedAt: { type: Date, default: null },
    ipHash: { type: String, default: '' },
    userAgent: { type: String, default: '' },
  },
  status: { type: String, default: 'active', enum: ['active', 'suspended', 'closed'] },
  fplManagerId: { type: String, default: '', trim: true },
  fantasyTeamName: { type: String, default: '' },
}, { timestamps: true });

userSchema.index(
  { fplManagerId: 1 },
  { unique: true, partialFilterExpression: { fplManagerId: { $type: 'string', $gt: '' } } }
);

const userProfileSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', unique: true, required: true, index: true },
  city: { type: String, default: '' },
  address: { type: String, default: '' },
  contactPreference: { type: String, default: 'email', enum: ['email', 'sms', 'phone'] },
  connectedAccounts: { type: Schema.Types.Mixed, default: {} },
  notificationPreferences: {
    type: Schema.Types.Mixed,
    default: {
      emailNotifications: true,
      smsNotifications: false,
      leagueReminders: true,
      deadlineReminders: true,
      transactions: true,
      results: true,
      marketing: false,
    },
  },
  profileCompletion: { type: Number, default: 20, min: 0, max: 100 },
  profilePicture: { type: String, default: '' },
  profilePicturePublicId: { type: String, default: '' },
  profilePictureFormat: { type: String, default: '' },
  profilePictureBytes: { type: Number, default: 0, min: 0 },
  profilePictureUpdatedAt: { type: Date, default: null },
}, { timestamps: true });

const waitlistEntrySchema = new Schema({
  fullName: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone: { type: String, required: true, trim: true },
  ageConfirmed: { type: Boolean, required: true },
  marketingConsent: { type: Boolean, default: false },
}, { timestamps: { createdAt: true, updatedAt: false } });

const leagueSchema = new Schema({
  name: { type: String, required: true, trim: true },
  description: { type: String, default: '' },
  competitionType: { type: String, required: true },
  ruleType: { type: String, default: 'highest-score' },
  cadence: { type: String, default: 'custom' },
  officialSupremeLeague: { type: Boolean, default: false },
  customLeague: { type: Boolean, default: true },
  inviteOnly: { type: Boolean, default: false },
  inviteCode: { type: String, default: '' },
  invitedUserId: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  invitedEmail: { type: String, default: '' },
  tieBreak: { type: String, default: 'overall-rank' },
  status: { type: String, default: 'open', enum: ['draft', 'open', 'full', 'upcoming', 'live', 'awaiting-review', 'settled', 'cancelled'] },
  startGameweek: { type: Number, required: true },
  endGameweek: { type: Number, required: true },
  currentGameweek: { type: Number, default: 1 },
  entryFeeCents: { type: Number, required: true, min: 0 },
  platformFeeBasisPoints: { type: Number, default: 1000 },
  grossPoolCents: { type: Number, default: 0 },
  projectedPrizeCents: { type: Number, default: 0 },
  displayedPrizeCents: { type: Number, default: 0 },
  guaranteedPrize: { type: Boolean, default: false },
  prizeType: { type: String, default: 'projected' },
  minimumParticipants: { type: Number, default: 2 },
  maximumParticipants: { type: Number, default: 100 },
  rules: { type: [String], default: [] },
  createdBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  expiresAt: { type: Date, default: null, index: true },
  fplJoinDeadlineAt: { type: Date, default: null, index: true },
  fplLastFixtureKickoffAt: { type: Date, default: null },
  fplFinishedAt: { type: Date, default: null, index: true },
  fplDataCheckedAt: { type: Date, default: null, index: true },
  completedAt: { type: Date, default: null },
  archivedAt: { type: Date, default: null },
  lastScoredAt: { type: Date, default: null },
  scoreThroughGameweek: { type: Number, default: 0 },
  scoreSyncStatus: { type: String, default: 'idle', enum: ['idle', 'syncing', 'success', 'partial', 'failed'] },
  scoreSyncMessage: { type: String, default: '' },
}, { timestamps: true });

leagueSchema.index(
  { inviteCode: 1 },
  { unique: true, partialFilterExpression: { inviteCode: { $type: 'string', $gt: '' } } }
);

const leagueEntrySchema = new Schema({
  leagueId: { type: Schema.Types.ObjectId, ref: 'League', required: true, index: true },
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  fantasyManagerId: { type: String, default: '' },
  joinedAt: { type: Date, default: null },
  paymentStatus: { type: String, default: 'pending', enum: ['pending', 'paid', 'failed', 'refunded'] },
  paymentTransactionId: { type: Schema.Types.ObjectId, ref: 'Transaction', default: null },
  paymentReference: { type: String, default: '' },
  paymentMethod: { type: String, default: '' },
  eligibilityStatus: { type: String, default: 'eligible', enum: ['eligible', 'warning', 'ineligible'] },
  eligibilityReason: { type: String, default: '' },
  lastConfirmedGameweek: { type: Number, default: 0 },
  consecutiveInactiveGameweeks: { type: Number, default: 0 },
  currentScore: { type: Number, default: 0 },
  currentRank: { type: Number, default: 0 },
  previousRank: { type: Number, default: 0 },
  prizeCents: { type: Number, default: 0 },
  payoutStatus: { type: String, default: 'none' },
  scoreThroughGameweek: { type: Number, default: 0 },
  lastScoreSyncAt: { type: Date, default: null },
  scoreSyncStatus: { type: String, default: 'idle', enum: ['idle', 'success', 'failed'] },
  scoreSyncError: { type: String, default: '' },
  latestOverallRank: { type: Number, default: 0 },
  scoreDetails: { type: Schema.Types.Mixed, default: {} },
}, { timestamps: true });
leagueEntrySchema.index({ leagueId: 1, userId: 1 }, { unique: true });

const walletSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', unique: true, required: true, index: true },
  walletIdentifier: { type: String, unique: true, sparse: true, index: true },
  currency: { type: String, default: 'USD' },
  availableBalanceCents: { type: Number, default: 0 },
  pendingBalanceCents: { type: Number, default: 0 },
  chargebackBalanceCents: { type: Number, default: 0 },
  lifetimeDepositsCents: { type: Number, default: 0 },
  lifetimeWithdrawalsCents: { type: Number, default: 0 },
  lifetimeEntryFeesCents: { type: Number, default: 0 },
  lifetimeSubscriptionFeesCents: { type: Number, default: 0 },
  lifetimePrizesCents: { type: Number, default: 0 },
  lifetimeRefundsCents: { type: Number, default: 0 },
  lifetimeAdjustmentsCents: { type: Number, default: 0 },
  seededAt: { type: Date, default: null },
  seedAmountCents: { type: Number, default: 0 },
  lastBalanceUpdateAt: { type: Date, default: Date.now },
  lastBalanceUpdateReason: { type: String, default: 'wallet-created' },
  lastBalanceUpdateFunction: { type: String, default: 'ensureUserResources' },
  appliedTransactionReferences: { type: [String], default: [] },
}, { timestamps: true });

const transactionSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  leagueId: { type: Schema.Types.ObjectId, ref: 'League', default: null },
  subscriptionId: { type: Schema.Types.ObjectId, ref: 'Subscription', default: null },
  reference: { type: String, required: true, unique: true, index: true },
  type: { type: String, required: true, enum: ['deposit', 'withdrawal', 'entry-fee', 'prize', 'refund', 'subscription', 'platform-fee', 'adjustment', 'reversal'] },
  direction: { type: String, required: true, enum: ['credit', 'debit'] },
  amountCents: { type: Number, required: true, min: 0 },
  currency: { type: String, default: 'USD' },
  provider: { type: String, default: 'mock' },
  providerReference: { type: String, default: '' },
  status: { type: String, required: true, enum: ['pending', 'processing', 'completed', 'rejected', 'reversed', 'cancelled'] },
  description: { type: String, required: true },
  metadata: { type: Schema.Types.Mixed, default: {} },
}, { timestamps: true });

transactionSchema.index(
  { userId: 1, type: 1, 'metadata.idempotencyKey': 1 },
  { unique: true, partialFilterExpression: { 'metadata.idempotencyKey': { $type: 'string' } } }
);

const subscriptionSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  planCode: { type: String, required: true },
  planName: { type: String, required: true },
  status: { type: String, default: 'pending-payment', enum: ['pending-payment', 'active', 'expired', 'replaced', 'cancelled', 'payment-failed'] },
  amountCents: { type: Number, required: true },
  billingInterval: { type: String, required: true },
  season: { type: String, default: 'Current Season' },
  competitionsIncluded: { type: [String], default: [] },
  startDate: { type: Date, default: null },
  activatedAt: { type: Date, default: null },
  renewalDate: { type: Date, default: null },
  endDate: { type: Date, default: null },
  validUntil: { type: Date, default: null, index: true },
  // Monthly Entry subscriptions are tied to one FPL calendar-month competition cycle.
  // These fields prevent a subscription that remains valid through the final GW from
  // accidentally qualifying for the next month's Supreme Monthly League.
  monthlyCycleKey: { type: String, default: '' },
  validThroughGameweek: { type: Number, default: null },
  lastValidityCheckAt: { type: Date, default: null },
  // Populated when an admin cancels a subscription made too late for its cycle
  // (e.g. joined after a league's cutoff) and refunds it to the member's wallet.
  cancelledAt: { type: Date, default: null },
  cancelledBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  cancellationReason: { type: String, default: '' },
  autoRenew: { type: Boolean, default: false },
  paymentTransactionId: { type: Schema.Types.ObjectId, ref: 'Transaction', default: null },
  paymentReference: { type: String, default: '' },
  paymentProvider: { type: String, default: 'paynow' },
  paymentMethod: { type: String, default: '' },
  walletSeedCents: { type: Number, default: 0 },
}, { timestamps: true });
subscriptionSchema.index(
  { paymentTransactionId: 1 },
  { unique: true, partialFilterExpression: { paymentTransactionId: { $type: 'objectId' } } }
);

const teamSnapshotSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  fantasyManagerId: { type: String, required: true },
  gameweek: Number,
  teamName: String,
  managerName: String,
  gameweekPoints: Number,
  totalPoints: Number,
  overallRank: Number,
  gameweekRank: Number,
  teamValue: Number,
  bank: Number,
  activeChip: String,
  lineup: { type: [Schema.Types.Mixed], default: [] },
  captain: String,
  viceCaptain: String,
  providerMode: { type: String, default: 'mock' },
  providerSource: { type: String, default: 'simulated-data-source' },
  syncStatus: { type: String, default: 'success' },
  lastSuccessfulSyncAt: { type: Date, default: Date.now },
  fetchedAt: { type: Date, default: Date.now },
}, { timestamps: true });

const auditLogSchema = new Schema({
  actorUserId: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  action: String,
  entityType: String,
  entityId: String,
  before: Schema.Types.Mixed,
  after: Schema.Types.Mixed,
  reason: String,
  requestId: String,
}, { timestamps: { createdAt: true, updatedAt: false } });



const maintenanceRunSchema = new Schema({
  _id: { type: String, required: true },
  runKey: { type: String, required: true, index: true },
  schedule: { type: String, default: 'daily' },
  scheduledForUtc: { type: Date, required: true },
  status: { type: String, enum: ['running', 'completed', 'failed'], default: 'running', index: true },
  startedAt: { type: Date, default: Date.now },
  completedAt: { type: Date, default: null },
  failedAt: { type: Date, default: null },
  tasks: { type: [String], default: [] },
  summary: { type: Schema.Types.Mixed, default: {} },
  error: { type: String, default: '' },
}, { timestamps: true });

const supportTicketSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  ticketNumber: { type: String, required: true, unique: true, index: true },
  subject: { type: String, required: true, trim: true, maxlength: 180 },
  category: { type: String, default: 'general', enum: ['general', 'account', 'league', 'payment', 'subscription', 'technical'] },
  priority: { type: String, default: 'normal', enum: ['low', 'normal', 'high', 'urgent'] },
  status: { type: String, default: 'open', enum: ['open', 'in-progress', 'waiting-user', 'resolved', 'closed'] },
  message: { type: String, required: true, trim: true, maxlength: 5000 },
  responses: [{
    authorId: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    authorRole: { type: String, enum: ['user', 'admin', 'system'], default: 'admin' },
    message: { type: String, required: true, trim: true, maxlength: 5000 },
    createdAt: { type: Date, default: Date.now },
  }],
  assignedTo: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  closedBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  closedAt: { type: Date, default: null },
  lastActivityAt: { type: Date, default: Date.now },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const UserProfile = mongoose.model('UserProfile', userProfileSchema);
const WaitlistEntry = mongoose.model('WaitlistEntry', waitlistEntrySchema);
const League = mongoose.model('League', leagueSchema);
const LeagueEntry = mongoose.model('LeagueEntry', leagueEntrySchema);
const Wallet = mongoose.model('Wallet', walletSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Subscription = mongoose.model('Subscription', subscriptionSchema);
const TeamSnapshot = mongoose.model('TeamSnapshot', teamSnapshotSchema);
const AuditLog = mongoose.model('AuditLog', auditLogSchema);
const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);
const MaintenanceRun = mongoose.model('MaintenanceRun', maintenanceRunSchema);

const { createLocalEmailService } = require('./local-email-service');
const emailService = createLocalEmailService({
  mongoose,
  User,
  UserProfile,
  League,
  LeagueEntry,
  Transaction,
  TeamSnapshot,
  clientOrigin: CLIENT_ORIGIN,
  normalizeEmail,
  normalizePaynowStatus,
});

// -----------------------------------------------------------------------------
// Shared configuration
// -----------------------------------------------------------------------------
const PLAN_CODES = Object.freeze({
  MONTHLY: 'monthly',
  PLUS: 'plus',
  HALF_SEASON: 'half-season',
  SEASON: 'season',
});

const PLANS = Object.freeze({
  monthly: { planCode: PLAN_CODES.MONTHLY, planName: 'Monthly Entry', amountCents: 200, billingInterval: 'monthly', validityDays: 30, competitionsIncluded: ['Supreme Monthly League'] },
  plus: { planCode: PLAN_CODES.PLUS, planName: 'Plus', amountCents: 500, billingInterval: 'monthly', validityDays: 30, competitionsIncluded: ['Monthly competitions', 'Selected bi-weekly competitions'] },
  halfSeason: { planCode: PLAN_CODES.HALF_SEASON, planName: 'Half-Season', amountCents: 2000, billingInterval: 'half-season', validityDays: 183, competitionsIncluded: ['Weekly competitions', 'Bi-weekly competitions', 'Monthly competitions', 'Half-season competition'] },
  season: { planCode: PLAN_CODES.SEASON, planName: 'Supreme Season Pass', amountCents: 4000, billingInterval: 'seasonal', validityDays: 365, competitionsIncluded: ['Qualifying Supreme-operated season-pass competitions'] },
});

function positiveIntegerFromEnv(name, fallback) {
  const parsed = Number(process.env[name]);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function nonNegativeIntegerFromEnv(name, fallback) {
  const parsed = Number(process.env[name]);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

const PUBLIC_PRIZE_SCHEDULE = Object.freeze({
  weekly: nonNegativeIntegerFromEnv('SUPREME_WEEKLY_PRIZE_CENTS', 1000),
  biWeekly: nonNegativeIntegerFromEnv('SUPREME_BIWEEKLY_PRIZE_CENTS', 1500),
  monthly: nonNegativeIntegerFromEnv('SUPREME_MONTHLY_PRIZE_CENTS', 3000),
  halfSeason: nonNegativeIntegerFromEnv('SUPREME_HALF_SEASON_PRIZE_CENTS', 10000),
  season: nonNegativeIntegerFromEnv('SUPREME_SEASON_PRIZE_CENTS', 30000),
});

const PUBLIC_MONTHLY_PRIZE_ROADMAP = Object.freeze([
  {
    activeSubscribers: positiveIntegerFromEnv('PUBLIC_MONTHLY_PRIZE_MILESTONE_1_USERS', 250),
    totalPrizeCents: nonNegativeIntegerFromEnv('PUBLIC_MONTHLY_PRIZE_MILESTONE_1_CENTS', 5000),
  },
  {
    activeSubscribers: positiveIntegerFromEnv('PUBLIC_MONTHLY_PRIZE_MILESTONE_2_USERS', 500),
    totalPrizeCents: nonNegativeIntegerFromEnv('PUBLIC_MONTHLY_PRIZE_MILESTONE_2_CENTS', 7500),
  },
  {
    activeSubscribers: positiveIntegerFromEnv('PUBLIC_MONTHLY_PRIZE_MILESTONE_3_USERS', 1000),
    totalPrizeCents: nonNegativeIntegerFromEnv('PUBLIC_MONTHLY_PRIZE_MILESTONE_3_CENTS', 12500),
  },
  {
    activeSubscribers: positiveIntegerFromEnv('PUBLIC_MONTHLY_PRIZE_MILESTONE_4_USERS', 2500),
    totalPrizeCents: nonNegativeIntegerFromEnv('PUBLIC_MONTHLY_PRIZE_MILESTONE_4_CENTS', 25000),
  },
]
  .filter((item) => item.totalPrizeCents >= PUBLIC_PRIZE_SCHEDULE.monthly)
  .sort((a, b) => a.activeSubscribers - b.activeSubscribers));

const PLAN_CODE_ALIASES = Object.freeze({
  monthly: PLAN_CODES.MONTHLY,
  'monthly-entry': PLAN_CODES.MONTHLY,
  '1-monthly-entry': PLAN_CODES.MONTHLY,
  plus: PLAN_CODES.PLUS,
  'plus-monthly': PLAN_CODES.PLUS,
  'plus-plan': PLAN_CODES.PLUS,
  '5-plus': PLAN_CODES.PLUS,
  'half-season': PLAN_CODES.HALF_SEASON,
  halfseason: PLAN_CODES.HALF_SEASON,
  '20-half-season': PLAN_CODES.HALF_SEASON,
  season: PLAN_CODES.SEASON,
  'season-pass': PLAN_CODES.SEASON,
  'supreme-season-pass': PLAN_CODES.SEASON,
  '40-supreme-season-pass': PLAN_CODES.SEASON,
});

function normalizeSubscriptionPlanCode(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[$£]/g, '')
    .replace(/[_\s]+/g, '-')
    .replace(/[^a-z0-9-]/g, '')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

function resolveSubscriptionPlan(value) {
  const normalized = normalizeSubscriptionPlanCode(value);
  const canonicalCode = PLAN_CODE_ALIASES[normalized] || normalized;
  return Object.values(PLANS).find((item) => item.planCode === canonicalCode) || null;
}

const PAYNOW_EXPRESS_METHODS = {
  ecocash: { code: 'ecocash', label: 'EcoCash', requiresPhone: true },
  onemoney: { code: 'onemoney', label: 'OneMoney', requiresPhone: true },
  innbucks: { code: 'innbucks', label: 'InnBucks', requiresPhone: true },
  omari: { code: 'omari', label: "O'mari", requiresPhone: true, requiresOtp: true },
};
const PAYMENT_METHODS = ['EcoCash', 'InnBucks', "O'mari", 'OneMoney', 'Bank Transfer'];
const WITHDRAWAL_MINIMUM_CENTS = 500;
const ZIMBABWE_USD_BANKS = ['BancABC Zimbabwe','CBZ Bank','CABS','Ecobank Zimbabwe','FBC Bank','First Capital Bank Zimbabwe','Nedbank Zimbabwe','NMB Bank Zimbabwe','Stanbic Bank Zimbabwe','Steward Bank','ZB Bank'];

// -----------------------------------------------------------------------------
// Fantasy data provider abstraction
// -----------------------------------------------------------------------------
const fplCache = new Map();

function normalizeManagerId(managerId) {
  const value = String(managerId || '').trim();
  if (!/^\d+$/.test(value)) {
    const error = new Error('Fantasy manager ID must contain numbers only.');
    error.status = 400;
    throw error;
  }
  return value;
}

async function assertFantasyManagerIdAvailable(managerId, currentUserId) {
  const existing = await User.findOne({
    fplManagerId: managerId,
    _id: { $ne: currentUserId },
  }).select('_id fullName').lean();
  if (existing) {
    const error = new Error('That FPL manager ID is already linked to another Supreme Fantasy League account.');
    error.status = 409;
    throw error;
  }
}

async function linkFantasyManagerToUser(user, managerId, teamName = '') {
  const normalized = normalizeManagerId(managerId);
  await assertFantasyManagerIdAvailable(normalized, user._id);

  if (user.fplManagerId && user.fplManagerId !== normalized) {
    const activeEntry = await LeagueEntry.findOne({ userId: user._id, paymentStatus: 'paid' })
      .populate({ path: 'leagueId', select: 'status expiresAt' })
      .lean();
    if (activeEntry?.leagueId && !leagueIsPast(activeEntry.leagueId)) {
      const error = new Error('You cannot change your FPL manager ID while you have an active paid league entry.');
      error.status = 409;
      throw error;
    }
  }

  user.fplManagerId = normalized;
  if (teamName) user.fantasyTeamName = teamName;
  try {
    await user.save();
  } catch (error) {
    if (error?.code === 11000) {
      const conflict = new Error('That FPL manager ID is already linked to another Supreme Fantasy League account.');
      conflict.status = 409;
      throw conflict;
    }
    throw error;
  }

  await LeagueEntry.updateMany(
    { userId: user._id, paymentStatus: { $ne: 'paid' } },
    { $set: { fantasyManagerId: normalized } }
  );
  return normalized;
}

async function fetchFplJson(resource, options = {}) {
  if (typeof fetch !== 'function') {
    const error = new Error('Public FPL syncing requires Node.js 18 or newer.');
    error.status = 500;
    throw error;
  }

  const cacheMinutes = Number.isFinite(options.cacheMinutes) ? options.cacheMinutes : FPL_CACHE_MINUTES;
  const cacheKey = resource;
  const cached = fplCache.get(cacheKey);
  if (!options.force && cached && cached.expiresAt > Date.now()) return cached.data;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FPL_REQUEST_TIMEOUT_MS);
  let response;

  try {
    response = await fetch(`${FPL_BASE_URL}${resource}`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'SupremeFantasyLeague/1.0',
      },
      signal: controller.signal,
    });
  } catch (error) {
    const providerError = new Error(error.name === 'AbortError'
      ? 'The FPL data request timed out. Try syncing again.'
      : 'The FPL data provider is currently unavailable. Try syncing again.');
    providerError.status = 503;
    providerError.cause = error;
    throw providerError;
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    const providerError = new Error(response.status === 404
      ? 'The FPL manager or gameweek data could not be found.'
      : `The FPL data provider returned HTTP ${response.status}.`);
    providerError.status = response.status === 404 ? 404 : 502;
    providerError.providerStatus = response.status;
    throw providerError;
  }

  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    const providerError = new Error('The FPL data provider returned an invalid response.');
    providerError.status = 502;
    throw providerError;
  }

  const data = await response.json();
  fplCache.set(cacheKey, { data, expiresAt: Date.now() + cacheMinutes * 60 * 1000 });
  return data;
}

const mockFantasyProvider = {
  async getGameState() {
    return {
      currentGameweek: 12,
      syncGameweek: 12,
      nextDeadline: new Date(Date.now() + 2 * 86400000).toISOString(),
      providerAvailable: true,
      providerMode: 'mock',
    };
  },
  async getManager(managerId) {
    const id = normalizeManagerId(managerId);
    return {
      managerName: 'Demo Manager',
      teamName: `Supreme XI ${id.slice(-3)}`,
      managerId: id,
      currentEvent: 12,
      summaryEventPoints: 68,
      summaryOverallPoints: 754,
      summaryOverallRank: 701245,
    };
  },
  async getManagerHistory() {
    return [
      { gameweek: 8, points: 64, totalPoints: 480, rank: 1350012, gameweekRank: 1300000, transferCost: 0, teamValue: 100.4, bank: 1.2 },
      { gameweek: 9, points: 71, totalPoints: 551, rank: 1110220, gameweekRank: 950000, transferCost: 4, teamValue: 100.7, bank: 0.8 },
      { gameweek: 10, points: 52, totalPoints: 603, rank: 1181200, gameweekRank: 2100000, transferCost: 0, teamValue: 100.9, bank: 0.5 },
      { gameweek: 11, points: 83, totalPoints: 686, rank: 812300, gameweekRank: 410000, transferCost: 0, teamValue: 101.1, bank: 0.9 },
      { gameweek: 12, points: 68, totalPoints: 754, rank: 701245, gameweekRank: 982100, transferCost: 0, teamValue: 101.3, bank: 0.7 },
    ];
  },
  async getManagerPicks(managerId, gameweek = 12) {
    normalizeManagerId(managerId);
    const names = ['A. Keeper', 'B. Defender', 'C. Defender', 'D. Defender', 'E. Midfielder', 'F. Midfielder', 'G. Midfielder', 'H. Midfielder', 'I. Forward', 'J. Forward', 'K. Forward', 'L. Bench', 'M. Bench', 'N. Bench', 'O. Bench'];
    const lineup = names.map((name, index) => ({
      elementId: index + 1,
      name,
      club: 'Demo',
      position: index === 0 ? 'GK' : index < 4 ? 'DEF' : index < 8 ? 'MID' : index < 11 ? 'FWD' : 'BENCH',
      lineupPosition: index + 1,
      multiplier: index === 5 ? 2 : index < 11 ? 1 : 0,
      points: Math.max(1, 10 - (index % 7)),
      contributionPoints: Math.max(1, 10 - (index % 7)) * (index === 5 ? 2 : index < 11 ? 1 : 0),
      isCaptain: index === 5,
      isViceCaptain: index === 8,
      starter: index < 11,
    }));
    return {
      gameweek: Number(gameweek),
      activeChip: null,
      lineup,
      entryHistory: { points: 68, total_points: 754, overall_rank: 701245, rank: 982100, value: 1013, bank: 7, event_transfers_cost: 0 },
    };
  },
  async getLiveGameweek(gameweek = 12) {
    return { gameweek: Number(gameweek), pointsByPlayer: new Map() };
  },
};

const publicFantasyProvider = {
  async getBootstrap(options = {}) {
    return fetchFplJson('/bootstrap-static/', options);
  },

  async getGameState() {
    const bootstrap = await this.getBootstrap();
    const events = Array.isArray(bootstrap.events) ? bootstrap.events : [];
    const current = events.find((event) => event.is_current);
    const next = events.find((event) => event.is_next);
    const lastFinished = [...events].reverse().find((event) => event.finished || event.data_checked);
    const currentGameweek = current?.id || lastFinished?.id || next?.id || 1;
    const syncGameweek = current?.id || lastFinished?.id || currentGameweek;
    return {
      currentGameweek,
      syncGameweek,
      nextDeadline: next?.deadline_time || current?.deadline_time || null,
      providerAvailable: true,
      providerMode: 'public',
    };
  },

  async getManager(managerId) {
    const id = normalizeManagerId(managerId);
    let entry;
    try {
      entry = await fetchFplJson(`/entry/${id}/`, { cacheMinutes: 2 });
    } catch (error) {
      if (error.providerStatus === 404) {
        error.message = 'No public FPL manager was found for that manager ID.';
      }
      throw error;
    }
    const fullName = [entry.player_first_name, entry.player_last_name].filter(Boolean).join(' ').trim();
    return {
      managerName: fullName || `FPL Manager ${id}`,
      teamName: entry.name || `FPL Team ${id}`,
      managerId: id,
      currentEvent: Number(entry.current_event || 0),
      summaryEventPoints: Number(entry.summary_event_points || 0),
      summaryOverallPoints: Number(entry.summary_overall_points || 0),
      summaryOverallRank: Number(entry.summary_overall_rank || 0),
      teamValue: Number(entry.last_deadline_value || 0) / 10,
      bank: Number(entry.last_deadline_bank || 0) / 10,
    };
  },

  async getManagerHistory(managerId) {
    const id = normalizeManagerId(managerId);
    const history = await fetchFplJson(`/entry/${id}/history/`, { cacheMinutes: 2 });
    return (history.current || []).map((item) => ({
      gameweek: Number(item.event),
      points: Number(item.points || 0),
      totalPoints: Number(item.total_points || 0),
      rank: Number(item.overall_rank || 0),
      gameweekRank: Number(item.rank || 0),
      transferCost: Number(item.event_transfers_cost || 0),
      transfers: Number(item.event_transfers || 0),
      pointsOnBench: Number(item.points_on_bench || 0),
      teamValue: Number(item.value || 0) / 10,
      bank: Number(item.bank || 0) / 10,
    }));
  },

  async getLiveGameweek(gameweek) {
    const eventId = Number(gameweek);
    if (!Number.isInteger(eventId) || eventId < 1) {
      const error = new Error('A valid FPL gameweek is required.');
      error.status = 400;
      throw error;
    }
    const live = await fetchFplJson(`/event/${eventId}/live/`, { cacheMinutes: 1 });
    const pointsByPlayer = new Map((live.elements || []).map((item) => [Number(item.id), Number(item.stats?.total_points || 0)]));
    return { gameweek: eventId, pointsByPlayer };
  },

  async getManagerPicks(managerId, gameweek) {
    const id = normalizeManagerId(managerId);
    const eventId = Number(gameweek);
    if (!Number.isInteger(eventId) || eventId < 1) {
      const error = new Error('A valid FPL gameweek is required.');
      error.status = 400;
      throw error;
    }

    const [picksData, bootstrap, live] = await Promise.all([
      fetchFplJson(`/entry/${id}/event/${eventId}/picks/`, { cacheMinutes: 2 }),
      this.getBootstrap(),
      this.getLiveGameweek(eventId),
    ]);

    const players = new Map((bootstrap.elements || []).map((player) => [Number(player.id), player]));
    const teams = new Map((bootstrap.teams || []).map((team) => [Number(team.id), team]));
    const positions = new Map((bootstrap.element_types || []).map((position) => [Number(position.id), position]));

    const lineup = (picksData.picks || []).map((pick) => {
      const player = players.get(Number(pick.element)) || {};
      const team = teams.get(Number(player.team)) || {};
      const position = positions.get(Number(player.element_type)) || {};
      const rawPoints = live.pointsByPlayer.get(Number(pick.element)) || 0;
      const multiplier = Number(pick.multiplier || 0);
      return {
        elementId: Number(pick.element),
        name: player.web_name || `Player ${pick.element}`,
        club: team.short_name || team.name || '',
        position: position.singular_name_short || position.singular_name || '',
        lineupPosition: Number(pick.position || 0),
        multiplier,
        points: rawPoints,
        contributionPoints: rawPoints * multiplier,
        isCaptain: Boolean(pick.is_captain),
        isViceCaptain: Boolean(pick.is_vice_captain),
        starter: Number(pick.position) <= 11,
      };
    });

    return {
      gameweek: eventId,
      activeChip: picksData.active_chip || null,
      lineup,
      entryHistory: picksData.entry_history || {},
      automaticSubs: picksData.automatic_subs || [],
    };
  },
};

if (!['mock', 'public'].includes(FPL_DATA_MODE)) {
  throw new Error('FPL_DATA_MODE must be either "mock" or "public". Production deployments must use "public".');
}

const fantasyProvider = FPL_DATA_MODE === 'public' ? publicFantasyProvider : mockFantasyProvider;

async function loadFantasyTeam(managerId) {
  const id = normalizeManagerId(managerId);
  const [gameState, manager, history] = await Promise.all([
    fantasyProvider.getGameState(),
    fantasyProvider.getManager(id),
    fantasyProvider.getManagerHistory(id),
  ]);

  const latestHistory = history.length ? history[history.length - 1] : null;
  let gameweek = Number(gameState.syncGameweek || manager.currentEvent || latestHistory?.gameweek || gameState.currentGameweek);
  let picks;

  try {
    picks = await fantasyProvider.getManagerPicks(id, gameweek);
  } catch (error) {
    const fallbackGameweek = Number(latestHistory?.gameweek || 0);
    if (error.providerStatus === 404 && fallbackGameweek && fallbackGameweek !== gameweek) {
      gameweek = fallbackGameweek;
      picks = await fantasyProvider.getManagerPicks(id, gameweek);
    } else if (error.providerStatus === 404) {
      const unavailable = new Error('This manager does not yet have a publicly available FPL team for the selected gameweek. Try again after the gameweek deadline.');
      unavailable.status = 409;
      throw unavailable;
    } else {
      throw error;
    }
  }

  const entry = picks.entryHistory || {};
  const historyForGameweek = history.find((item) => item.gameweek === gameweek) || latestHistory || {};
  const captain = picks.lineup.find((player) => player.isCaptain)?.name || '';
  const viceCaptain = picks.lineup.find((player) => player.isViceCaptain)?.name || '';
  const fetchedAt = new Date();

  return {
    manager,
    history,
    gameState,
    snapshot: {
      fantasyManagerId: id,
      gameweek,
      teamName: manager.teamName,
      managerName: manager.managerName,
      gameweekPoints: Number(entry.points ?? historyForGameweek.points ?? manager.summaryEventPoints ?? 0),
      totalPoints: Number(entry.total_points ?? historyForGameweek.totalPoints ?? manager.summaryOverallPoints ?? 0),
      overallRank: Number(entry.overall_rank ?? historyForGameweek.rank ?? manager.summaryOverallRank ?? 0),
      gameweekRank: Number(entry.rank ?? historyForGameweek.gameweekRank ?? 0),
      teamValue: Number(entry.value != null ? entry.value / 10 : historyForGameweek.teamValue ?? manager.teamValue ?? 0),
      bank: Number(entry.bank != null ? entry.bank / 10 : historyForGameweek.bank ?? manager.bank ?? 0),
      activeChip: picks.activeChip || 'None',
      lineup: picks.lineup,
      captain,
      viceCaptain,
      providerMode: FPL_DATA_MODE,
      providerSource: FPL_DATA_MODE === 'public' ? 'fantasy.premierleague.com' : 'simulated-data-source',
      syncStatus: 'success',
      lastSuccessfulSyncAt: fetchedAt,
      fetchedAt,
    },
  };
}

async function persistFantasyTeamSnapshot(user, { force = true } = {}) {
  if (!user?.fplManagerId) return { snapshot: null, manager: null, history: [], linked: false };
  const existing = await TeamSnapshot.findOne({ userId: user._id, providerMode: FPL_DATA_MODE })
    .sort({ fetchedAt: -1, updatedAt: -1 });
  const freshnessMs = Math.max(0, FPL_PAGE_REFRESH_CACHE_MINUTES) * 60 * 1000;
  if (!force && existing?.fetchedAt && Date.now() - new Date(existing.fetchedAt).getTime() < freshnessMs) {
    return { snapshot: existing.toObject(), manager: null, history: [], linked: true, cached: true };
  }

  const providerData = await loadFantasyTeam(user.fplManagerId);
  const normalizedSnapshot = providerData.snapshot;
  const snapshot = await TeamSnapshot.findOneAndUpdate(
    { userId: user._id, gameweek: normalizedSnapshot.gameweek, providerMode: normalizedSnapshot.providerMode },
    { $set: { ...normalizedSnapshot, userId: user._id } },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
  if (providerData.manager?.teamName && providerData.manager.teamName !== user.fantasyTeamName) {
    await User.updateOne({ _id: user._id }, { $set: { fantasyTeamName: providerData.manager.teamName } });
    user.fantasyTeamName = providerData.manager.teamName;
  }
  return { ...providerData, snapshot, linked: true, cached: false };
}

// -----------------------------------------------------------------------------
// Express middleware
// -----------------------------------------------------------------------------
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  credentials: true,
  origin(origin, callback) {
    // Requests without an Origin header include server-to-server callbacks and cron jobs.
    if (!origin) return callback(null, true);
    if (isAllowedOrigin(origin)) return callback(null, true);
    const error = new Error('Origin is not allowed by CORS.');
    error.status = 403;
    return callback(error);
  },
}));
app.use(express.json({ limit: '4mb' }));
app.use(express.urlencoded({ extended: false, limit: '256kb' }));
app.use(cookieParser());
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || crypto.randomUUID();
  res.setHeader('X-Request-ID', req.requestId);
  next();
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
const writeLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });

function signToken(user) {
  return jwt.sign({ sub: user._id.toString(), role: user.role }, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function setSessionCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: IS_PRODUCTION ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  });
}

const LEGAL_ACCEPTANCE_EXEMPT_PATHS = new Set([
  '/api/auth/me',
  '/api/auth/accept-legal',
]);

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies[COOKIE_NAME];
    if (!token) return failure(res, 401, 'Authentication required.');
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.sub);
    if (!user || user.status !== 'active') return failure(res, 401, 'Session is no longer valid.');
    req.user = user;
    if (user.role === 'user' && !userHasCurrentLegalAcceptance(user) && !LEGAL_ACCEPTANCE_EXEMPT_PATHS.has(req.path)) {
      return failure(res, 428, 'Review and accept the current Terms, Privacy Policy, Competition Rules and security notice to continue.');
    }
    next();
  } catch (error) {
    return failure(res, 401, 'Session expired. Please log in again.');
  }
}

async function logAudit(req, action, entityType, entityId, before, after, reason = '') {
  try {
    await AuditLog.create({ actorUserId: req.user?._id || null, action, entityType, entityId: String(entityId || ''), before, after, reason, requestId: req.requestId });
  } catch (error) {
    console.error('Audit log write failed', req.requestId, error.message);
  }
}

async function ensureUserResources(userId) {
  const walletIdentifier = walletIdentifierFor(userId);
  const [profile, wallet] = await Promise.all([
    UserProfile.findOneAndUpdate({ userId }, { $setOnInsert: { userId } }, { upsert: true, new: true }),
    Wallet.findOneAndUpdate(
      { userId },
      {
        $setOnInsert: {
          userId,
          availableBalanceCents: MOCK_PAYMENTS ? 5000 : 0,
          currency: 'USD',
          lastBalanceUpdateAt: new Date(),
          lastBalanceUpdateReason: 'wallet-created',
          lastBalanceUpdateFunction: 'ensureUserResources',
        },
        $set: { walletIdentifier },
      },
      { upsert: true, new: true }
    ),
  ]);
  return { profile, wallet };
}

async function updateWalletBalances(userId, increments, reason, functionName, extraSet = {}, operationReference = '') {
  const cleaned = Object.fromEntries(Object.entries(increments || {}).filter(([, value]) => Number(value) !== 0));
  const query = { userId, ...(operationReference ? { appliedTransactionReferences: { $ne: operationReference } } : {}) };
  const update = {
    $set: {
      lastBalanceUpdateAt: new Date(),
      lastBalanceUpdateReason: reason,
      lastBalanceUpdateFunction: functionName,
      ...extraSet,
    },
  };
  if (Object.keys(cleaned).length) update.$inc = cleaned;
  if (operationReference) update.$addToSet = { appliedTransactionReferences: operationReference };
  const wallet = await Wallet.findOneAndUpdate(query, update, { new: true });
  return wallet || Wallet.findOne({ userId });
}

async function walletOperationApplied(userId, operationReference) {
  return Boolean(await Wallet.exists({ userId, appliedTransactionReferences: operationReference }));
}

function utcMonthKey(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
}

// Best-effort boundary for monthly-billed plans when the live FPL fixture calendar
// can't be consulted (FPL_DATA_MODE is "mock", or the FPL API is unreachable). This
// still anchors the expiry to the UTC calendar month the subscription was purchased
// for — the first moment of the following month — instead of a flat N-day rolling
// window from the purchase date. It is intentionally independent of FPL_DATA_MODE so
// that billing periods stay calendar-correct even when gameplay data is mocked.
function monthlyCalendarBoundaryWindow(startDate) {
  const anchor = new Date(startDate);
  if (Number.isNaN(anchor.getTime())) throw new Error('Monthly subscription start date is invalid.');
  const targetYear = anchor.getUTCFullYear();
  const targetMonth = anchor.getUTCMonth();
  const validUntil = new Date(Date.UTC(targetYear, targetMonth + 1, 1, 0, 0, 0, 0));
  return {
    monthlyCycleKey: `${targetYear}-${String(targetMonth + 1).padStart(2, '0')}`,
    startGameweek: null,
    validThroughGameweek: null,
    validUntil,
    cycleFinished: validUntil <= new Date(),
  };
}

function monthlySubscriptionWindowFromBootstrap(startDate, bootstrap) {
  const anchor = new Date(startDate);
  if (Number.isNaN(anchor.getTime())) throw new Error('Monthly subscription start date is invalid.');

  const events = (Array.isArray(bootstrap?.events) ? bootstrap.events : [])
    .filter((event) => event?.deadline_time && Number.isFinite(new Date(event.deadline_time).getTime()))
    .sort((a, b) => new Date(a.deadline_time) - new Date(b.deadline_time));

  if (!events.length) throw new Error('FPL did not return a usable gameweek schedule.');

  let targetYear = anchor.getUTCFullYear();
  let targetMonth = anchor.getUTCMonth();
  let cycleEvents = events.filter((event) => {
    const deadline = new Date(event.deadline_time);
    return deadline.getUTCFullYear() === targetYear && deadline.getUTCMonth() === targetMonth;
  });

  // During an off-season month with no FPL deadline, sell access to the next
  // scheduled FPL month rather than creating an arbitrary 30-day entitlement.
  if (!cycleEvents.length) {
    const nextEvent = events.find((event) => new Date(event.deadline_time) >= anchor);
    if (!nextEvent) throw new Error('No future FPL gameweek is available for a monthly subscription.');
    const nextDeadline = new Date(nextEvent.deadline_time);
    targetYear = nextDeadline.getUTCFullYear();
    targetMonth = nextDeadline.getUTCMonth();
    cycleEvents = events.filter((event) => {
      const deadline = new Date(event.deadline_time);
      return deadline.getUTCFullYear() === targetYear && deadline.getUTCMonth() === targetMonth;
    });
  }

  if (!cycleEvents.length) throw new Error('No FPL gameweeks were found for the monthly subscription cycle.');

  const firstEvent = cycleEvents[0];
  const lastEvent = cycleEvents[cycleEvents.length - 1];
  const lastDeadline = new Date(lastEvent.deadline_time);
  const nextEvent = events.find((event) => new Date(event.deadline_time) > lastDeadline);

  // FPL bootstrap exposes deadlines and a finished flag, not a canonical final-whistle
  // timestamp. The next FPL deadline is therefore the safe time boundary; the daily
  // reconciler expires the subscription earlier as soon as the final GW is marked finished.
  const validUntil = nextEvent?.deadline_time
    ? new Date(nextEvent.deadline_time)
    : new Date(lastDeadline.getTime() + 8 * 86400000);

  return {
    monthlyCycleKey: `${targetYear}-${String(targetMonth + 1).padStart(2, '0')}`,
    startGameweek: Number(firstEvent.id),
    validThroughGameweek: Number(lastEvent.id),
    validUntil,
    cycleFinished: Boolean(lastEvent.finished || lastEvent.data_checked),
  };
}

async function subscriptionDates(plan, startDate = new Date()) {
  const fallbackValidUntil = new Date(startDate.getTime() + Number(plan.validityDays || 30) * 86400000);
  const fallback = {
    startDate,
    activatedAt: startDate,
    validUntil: fallbackValidUntil,
    endDate: fallbackValidUntil,
    renewalDate: plan.billingInterval === 'monthly' ? fallbackValidUntil : null,
    monthlyCycleKey: '',
    validThroughGameweek: null,
  };

  // A monthly-billed plan must always lapse at the end of the calendar month it was
  // purchased for, never a flat validityDays window from the purchase timestamp
  // (that was the source of subscriptions "lapsing a month after the sub" no matter
  // where in the month they were bought). This applies regardless of FPL_DATA_MODE,
  // since billing-cycle boundaries are a real-world calendar concept even when
  // gameplay data is mocked for testing.
  if (plan?.billingInterval !== 'monthly') return fallback;

  const calendarWindow = monthlyCalendarBoundaryWindow(startDate);
  const calendarFallback = {
    ...fallback,
    validUntil: calendarWindow.validUntil,
    endDate: calendarWindow.validUntil,
    renewalDate: calendarWindow.validUntil,
    monthlyCycleKey: calendarWindow.monthlyCycleKey,
    validThroughGameweek: null,
  };

  if (FPL_DATA_MODE !== 'public') return calendarFallback;

  try {
    const bootstrap = await fetchFplJson('/bootstrap-static/', { cacheMinutes: 5 });
    const window = monthlySubscriptionWindowFromBootstrap(startDate, bootstrap);
    return {
      ...fallback,
      validUntil: window.validUntil,
      endDate: window.validUntil,
      renewalDate: window.validUntil,
      monthlyCycleKey: window.monthlyCycleKey,
      validThroughGameweek: window.validThroughGameweek,
    };
  } catch (error) {
    // Fall back to the pure calendar-month boundary, not the flat validityDays
    // window, so the subscription still lapses at month-end even when FPL is
    // temporarily unreachable. Daily maintenance will re-align it to the precise
    // fixture deadline once the provider recovers.
    console.warn('Monthly subscription schedule fallback used:', error.message);
    return calendarFallback;
  }
}

async function reconcileMonthlySubscriptionWindows({ userId = null } = {}) {
  // Runs regardless of FPL_DATA_MODE: billing-cycle boundaries are a calendar
  // concept, not gameplay data, so mocked deployments must still reconcile monthly
  // subscriptions to a month-end boundary instead of skipping entirely (which left
  // subscriptions created under the old flat validityDays window uncorrected).
  const now = new Date();
  let bootstrap = null;
  if (FPL_DATA_MODE === 'public') {
    try {
      bootstrap = await fetchFplJson('/bootstrap-static/', { cacheMinutes: 5 });
    } catch (error) {
      console.warn('Monthly subscription reconciliation: FPL fixtures unavailable, using calendar-month fallback:', error.message);
    }
  }
  const query = {
    billingInterval: 'monthly',
    status: { $in: ['active', 'expired'] },
    ...(userId ? { userId } : {}),
  };
  const subscriptions = await Subscription.find(query).sort({ activatedAt: 1, createdAt: 1 });

  let corrected = 0;
  let reactivated = 0;
  let expired = 0;
  let unchanged = 0;
  let failed = 0;

  for (const subscription of subscriptions) {
    try {
      const anchor = subscription.activatedAt || subscription.startDate || subscription.createdAt;
      let window;
      try {
        window = bootstrap
          ? monthlySubscriptionWindowFromBootstrap(anchor, bootstrap)
          : monthlyCalendarBoundaryWindow(anchor);
      } catch (windowError) {
        // e.g. an off-season anchor month with no upcoming FPL gameweek yet.
        window = monthlyCalendarBoundaryWindow(anchor);
      }
      const timeBoundaryPassed = window.validUntil <= now;
      const shouldBeExpired = window.cycleFinished || timeBoundaryPassed;

      const targetStatus = shouldBeExpired ? 'expired' : 'active';
      let targetValidUntil = window.validUntil;

      // If FPL explicitly marks the final monthly GW finished before the fallback
      // boundary, expire now. Preserve an already-recorded earlier expiry on reruns.
      if (window.cycleFinished && subscription.status === 'active') {
        targetValidUntil = now;
      } else if (
        window.cycleFinished
        && subscription.status === 'expired'
        && subscription.validUntil
        && new Date(subscription.validUntil) <= now
      ) {
        targetValidUntil = new Date(subscription.validUntil);
      }

      const currentValidUntil = subscription.validUntil ? new Date(subscription.validUntil).getTime() : null;
      const currentEndDate = subscription.endDate ? new Date(subscription.endDate).getTime() : null;
      const currentRenewalDate = subscription.renewalDate ? new Date(subscription.renewalDate).getTime() : null;
      const targetMs = targetValidUntil.getTime();

      const changed = (
        subscription.status !== targetStatus
        || String(subscription.monthlyCycleKey || '') !== window.monthlyCycleKey
        || Number(subscription.validThroughGameweek || 0) !== Number(window.validThroughGameweek || 0)
        || currentValidUntil !== targetMs
        || currentEndDate !== targetMs
        || currentRenewalDate !== targetMs
      );

      if (!changed) {
        unchanged += 1;
        continue;
      }

      if (subscription.status === 'expired' && targetStatus === 'active') reactivated += 1;
      if (subscription.status === 'active' && targetStatus === 'expired') expired += 1;

      await Subscription.updateOne(
        { _id: subscription._id },
        {
          $set: {
            status: targetStatus,
            monthlyCycleKey: window.monthlyCycleKey,
            validThroughGameweek: window.validThroughGameweek,
            validUntil: targetValidUntil,
            endDate: targetValidUntil,
            renewalDate: targetValidUntil,
            lastValidityCheckAt: now,
          },
        }
      );
      corrected += 1;
    } catch (error) {
      failed += 1;
      console.error('Monthly subscription reconciliation failed', subscription._id, error.message);
    }
  }

  return {
    skipped: false,
    checked: subscriptions.length,
    corrected,
    reactivated,
    expired,
    unchanged,
    failed,
  };
}

async function expireSubscriptions(userId = null) {
  const now = new Date();
  const query = {
    status: 'active',
    ...(userId ? { userId } : {}),
    $or: [
      { validUntil: { $lte: now } },
      { validUntil: null, endDate: { $lte: now } },
      { validUntil: null, endDate: null, renewalDate: { $lte: now } },
    ],
  };
  await Subscription.updateMany(query, { $set: { status: 'expired', lastValidityCheckAt: now } });
  await Subscription.updateMany(
    { status: 'active', ...(userId ? { userId } : {}) },
    { $set: { lastValidityCheckAt: now } }
  );
}

async function currentSubscription(userId) {
  await expireSubscriptions(userId);
  return Subscription.findOne({ userId, status: 'active' }).sort({ activatedAt: -1, createdAt: -1 }).lean();
}

function parsePaynowMessage(message) {
  const entries = [];
  const params = message instanceof URLSearchParams ? message : new URLSearchParams(String(message || ''));
  for (const [key, value] of params.entries()) entries.push([String(key).toLowerCase(), value]);
  return { entries, data: Object.fromEntries(entries) };
}

function paynowHash(entries) {
  const joined = entries
    .filter(([key]) => String(key).toLowerCase() !== 'hash')
    .map(([, value]) => String(value ?? ''))
    .join('');
  return crypto.createHash('sha512').update(`${joined}${PAYNOW_INTEGRATION_KEY}`, 'utf8').digest('hex').toUpperCase();
}

function paynowHashIsValid(parsed) {
  const supplied = String(parsed?.data?.hash || '').toUpperCase();
  if (!supplied || !PAYNOW_INTEGRATION_KEY) return false;
  const expected = paynowHash(parsed.entries);
  if (supplied.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
}

function assertPaynowUrl(value) {
  const url = new URL(value);
  const hostname = url.hostname.toLowerCase();
  if (!(hostname === 'paynow.co.zw' || hostname.endsWith('.paynow.co.zw'))) {
    const error = new Error('Paynow returned an unexpected payment URL.');
    error.status = 502;
    throw error;
  }
  return url.toString();
}

async function postPaynow(url, fields, { requireHash = true } = {}) {
  const destination = assertPaynowUrl(url);
  const entries = Object.entries(fields).filter(([, value]) => value !== undefined && value !== null && value !== '');
  const body = new URLSearchParams([...entries, ['hash', paynowHash(entries)]]);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PAYNOW_REQUEST_TIMEOUT_MS);
  let response;
  try {
    response = await fetch(destination, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: controller.signal,
    });
  } catch (error) {
    const wrapped = new Error(error.name === 'AbortError' ? 'Paynow did not respond before the request timed out.' : 'Unable to reach Paynow.');
    wrapped.status = 502;
    throw wrapped;
  } finally {
    clearTimeout(timeout);
  }
  const text = await response.text();
  const parsed = parsePaynowMessage(text);
  const responseStatus = normalizePaynowStatus(parsed.data.status);
  if (requireHash && responseStatus !== 'error' && (!parsed.data.hash || !paynowHashIsValid(parsed))) {
    const error = new Error('Paynow returned a response with an invalid security hash.');
    error.status = 502;
    throw error;
  }
  if (!response.ok || responseStatus === 'error') {
    const error = new Error(parsed.data.error || 'Paynow rejected the payment request.');
    error.status = 502;
    throw error;
  }
  return parsed.data;
}

function paymentPublicView(transaction) {
  const metadata = transaction?.metadata || {};
  return {
    reference: transaction.reference,
    transactionId: transaction._id,
    type: transaction.type,
    amountCents: transaction.amountCents,
    currency: transaction.currency,
    status: transaction.status,
    method: metadata.method || '',
    paynowStatus: metadata.paynowStatus || '',
    instructions: metadata.instructions || '',
    authorizationCode: metadata.authorizationCode || '',
    authorizationExpires: metadata.authorizationExpires || '',
    deepLink: metadata.deepLink || '',
    otpReference: metadata.otpReference || '',
    requiresOtp: Boolean(metadata.remoteOtpUrl && !metadata.otpSubmittedAt),
    completed: transaction.status === 'completed',
    terminal: ['completed', 'rejected', 'cancelled', 'reversed'].includes(transaction.status),
  };
}

async function initiatePaynowExpress({ reference, amountCents, description, user, method, phone }) {
  const methodConfig = PAYNOW_EXPRESS_METHODS[method];
  if (!methodConfig) {
    const error = new Error('Select EcoCash, OneMoney, InnBucks or O\'mari.');
    error.status = 400;
    throw error;
  }
  const normalizedPhone = normalizeZimbabwePhone(phone);
  if (methodConfig.requiresPhone && !normalizedPhone) {
    const error = new Error('Enter a valid Zimbabwe mobile number.');
    error.status = 400;
    throw error;
  }
  if (PAYNOW_TEST_MODE && !PAYNOW_TEST_AUTH_EMAIL) {
    const error = new Error('PAYNOW_TEST_AUTH_EMAIL is required while Paynow is in test mode.');
    error.status = 500;
    throw error;
  }
  const paynowAuthEmail = PAYNOW_TEST_MODE ? PAYNOW_TEST_AUTH_EMAIL : normalizeEmail(user.email);
  const fields = {
    id: PAYNOW_INTEGRATION_ID,
    reference,
    amount: (amountCents / 100).toFixed(2),
    additionalinfo: description,
    returnurl: PAYNOW_RETURN_URL,
    resulturl: PAYNOW_RESULT_URL,
    authemail: paynowAuthEmail,
    authphone: normalizedPhone,
    authname: user.fullName,
    merchanttrace: reference.slice(0, 32),
    status: 'Message',
    method,
    phone: normalizedPhone,
  };
  const response = await postPaynow('https://www.paynow.co.zw/interface/remotetransaction', fields);
  if (response.pollurl) assertPaynowUrl(response.pollurl);
  if (response.remoteotpurl) assertPaynowUrl(response.remoteotpurl);
  return {
    ...response,
    normalizedPhone,
    deepLink: response.authorizationcode ? `com.innbucks.customer://purchase?paymentToken=${encodeURIComponent(response.authorizationcode)}` : '',
  };
}

async function pollPaynowTransaction(transaction) {
  const pollUrl = transaction?.metadata?.pollUrl;
  if (!pollUrl) return null;
  const destination = assertPaynowUrl(pollUrl);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PAYNOW_REQUEST_TIMEOUT_MS);
  let response;
  try {
    response = await fetch(destination, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: '',
      signal: controller.signal,
    });
  } catch (error) {
    const wrapped = new Error(error.name === 'AbortError' ? 'Paynow status check timed out.' : 'Unable to check the Paynow payment status.');
    wrapped.status = 502;
    throw wrapped;
  } finally {
    clearTimeout(timeout);
  }
  const parsed = parsePaynowMessage(await response.text());
  if (!parsed.data.hash || !paynowHashIsValid(parsed)) {
    const error = new Error('Paynow returned a status response with an invalid security hash.');
    error.status = 502;
    throw error;
  }
  if (!response.ok || normalizePaynowStatus(parsed.data.status) === 'error') {
    const error = new Error(parsed.data.error || 'Paynow could not return the payment status.');
    error.status = 502;
    throw error;
  }
  return parsed.data;
}

async function releasePendingDeposit(transaction, reason, status = 'rejected') {
  if (transaction.type !== 'deposit' || transaction.metadata?.pendingReleasedAt) return transaction;
  const pendingApplied = await walletOperationApplied(transaction.userId, `${transaction.reference}:pending`);
  if (pendingApplied) {
    await updateWalletBalances(
      transaction.userId,
      { pendingBalanceCents: -transaction.amountCents },
      reason,
      'releasePendingDeposit',
      {},
      `${transaction.reference}:pending-release`
    );
  }
  const releasedTransaction = await Transaction.findByIdAndUpdate(
    transaction._id,
    { $set: { status, 'metadata.pendingReleasedAt': new Date(), 'metadata.paynowStatus': reason } },
    { new: true }
  );
  await emailService.notifyPaymentUpdate(releasedTransaction);
  return releasedTransaction;
}

async function seedWalletAfterSubscription(userId, sourceTransaction) {
  const now = new Date();
  const seededWallet = await Wallet.findOneAndUpdate(
    { userId, seededAt: null },
    {
      ...(SUBSCRIPTION_WALLET_SEED_CENTS > 0 ? { $inc: { availableBalanceCents: SUBSCRIPTION_WALLET_SEED_CENTS } } : {}),
      $set: {
        seededAt: now,
        seedAmountCents: SUBSCRIPTION_WALLET_SEED_CENTS,
        lastBalanceUpdateAt: now,
        lastBalanceUpdateReason: 'first-successful-subscription',
        lastBalanceUpdateFunction: 'seedWalletAfterSubscription',
      },
    },
    { new: true }
  );
  if (SUBSCRIPTION_WALLET_SEED_CENTS > 0) {
    await Transaction.findOneAndUpdate(
      { reference: `SEED-${String(userId).toUpperCase()}` },
      {
        $setOnInsert: {
          userId,
          reference: `SEED-${String(userId).toUpperCase()}`,
          type: 'adjustment',
          direction: 'credit',
          amountCents: SUBSCRIPTION_WALLET_SEED_CENTS,
          currency: 'USD',
          provider: 'internal-wallet-seed',
          status: 'completed',
          description: 'Initial wallet seed after first successful subscription',
          metadata: { sourceTransactionReference: sourceTransaction.reference },
        },
      },
      { upsert: true, new: true }
    );
  }
  return seededWallet;
}

async function finalizeSuccessfulPayment(transaction, paynowData) {
  const lockThreshold = new Date(Date.now() - 5 * 60 * 1000);
  const locked = await Transaction.findOneAndUpdate(
    {
      _id: transaction._id,
      'metadata.finalizedAt': { $exists: false },
      $or: [
        { 'metadata.finalizingAt': { $exists: false } },
        { 'metadata.finalizingAt': { $lte: lockThreshold } },
      ],
    },
    {
      $set: {
        status: 'processing',
        providerReference: paynowData.paynowreference || transaction.providerReference || '',
        'metadata.finalizingAt': new Date(),
        'metadata.paynowStatus': paynowData.status || 'Paid',
        'metadata.paymentChannel': paynowData.paymentchannel || transaction.metadata?.paymentChannel || '',
        'metadata.paymentInstrument': paynowData.paymentinstrument || transaction.metadata?.paymentInstrument || '',
      },
    },
    { new: true }
  );
  if (!locked) return Transaction.findById(transaction._id);

  try {
    await ensureUserResources(locked.userId);
    if (locked.type === 'deposit') {
      const pendingApplied = await walletOperationApplied(locked.userId, `${locked.reference}:pending`);
      await updateWalletBalances(
        locked.userId,
        {
          availableBalanceCents: locked.amountCents,
          pendingBalanceCents: pendingApplied ? -locked.amountCents : 0,
          lifetimeDepositsCents: locked.amountCents,
        },
        `Paynow deposit ${locked.reference} completed`,
        'finalizeSuccessfulPayment',
        {},
        `${locked.reference}:complete`
      );
    }

    if (locked.type === 'subscription') {
      const subscription = await Subscription.findById(locked.subscriptionId || locked.metadata?.subscriptionId);
      if (!subscription) throw new Error('The pending subscription record could not be found.');
      const plan = resolveSubscriptionPlan(subscription.planCode);
      if (!plan) throw new Error('The subscription plan is no longer available.');
      const dates = await subscriptionDates(plan);
      await Subscription.updateMany(
        { userId: locked.userId, status: 'active', _id: { $ne: subscription._id } },
        { $set: { status: 'replaced', endDate: new Date(), validUntil: new Date(), lastValidityCheckAt: new Date() } }
      );
      await Subscription.findByIdAndUpdate(subscription._id, {
        $set: {
          status: 'active',
          ...dates,
          lastValidityCheckAt: new Date(),
          walletSeedCents: SUBSCRIPTION_WALLET_SEED_CENTS,
        },
      });
      await updateWalletBalances(
        locked.userId,
        { lifetimeSubscriptionFeesCents: locked.amountCents },
        `Subscription payment ${locked.reference} completed`,
        'finalizeSuccessfulPayment',
        {},
        `${locked.reference}:complete`
      );
      await seedWalletAfterSubscription(locked.userId, locked);
    }

    if (locked.type === 'entry-fee') {
      const league = await League.findById(locked.leagueId || locked.metadata?.leagueId);
      const entry = await LeagueEntry.findById(locked.metadata?.leagueEntryId);
      if (!league || !entry) throw new Error('The pending league entry could not be found.');
      if (String(entry.userId) !== String(locked.userId)) throw new Error('The league entry does not belong to this payment.');

      const alreadyPaid = entry.paymentStatus === 'paid';
      if (!alreadyPaid) {
        const paidCount = await LeagueEntry.countDocuments({ leagueId: league._id, paymentStatus: 'paid' });
        if (paidCount >= league.maximumParticipants) throw new Error('The league filled before this payment could be finalised.');
        entry.paymentStatus = 'paid';
        entry.joinedAt = new Date();
        entry.paymentTransactionId = locked._id;
        entry.paymentReference = locked.reference;
        entry.paymentMethod = locked.metadata?.method || '';
        entry.currentRank = paidCount + 1;
        entry.previousRank = paidCount + 1;
        await entry.save();
      }

      const updatedPaidCount = await LeagueEntry.countDocuments({ leagueId: league._id, paymentStatus: 'paid' });
      if (league.competitionType === 'band-for-band') league.status = updatedPaidCount >= 2 ? 'live' : 'upcoming';
      else if (updatedPaidCount >= league.maximumParticipants) league.status = 'full';
      else if (league.status === 'draft') league.status = 'open';
      await league.save();

      await updateWalletBalances(
        locked.userId,
        { lifetimeEntryFeesCents: locked.amountCents },
        `League entry payment ${locked.reference} completed`,
        'finalizeSuccessfulPayment',
        {},
        `${locked.reference}:complete`
      );
    }

    const completedTransaction = await Transaction.findByIdAndUpdate(
      locked._id,
      {
        $set: {
          status: 'completed',
          'metadata.finalizedAt': new Date(),
          'metadata.paynowStatus': paynowData.status || 'Paid',
          'metadata.pollUrl': paynowData.pollurl || locked.metadata?.pollUrl || '',
        },
        $unset: { 'metadata.finalizingAt': 1 },
      },
      { new: true }
    );
    await emailService.notifyPaymentUpdate(completedTransaction);
    if (completedTransaction.type === 'entry-fee' && completedTransaction.leagueId) {
      await emailService.notifyLeagueMembership(completedTransaction.userId, completedTransaction.leagueId, 'Paynow checkout');
    }
    if (['subscription', 'entry-fee'].includes(completedTransaction.type)) {
      await localGrowth.processReferralRewards().catch((rewardError) => {
        console.error('Referral reward processing failed after payment:', rewardError.message);
      });
    }
    return completedTransaction;
  } catch (error) {
    await Transaction.updateOne(
      { _id: locked._id },
      { $set: { status: 'pending', 'metadata.finalizationError': error.message }, $unset: { 'metadata.finalizingAt': 1 } }
    );
    throw error;
  }
}

async function reverseCompletedPayment(transaction, paynowData) {
  if (transaction.status !== 'completed' || transaction.metadata?.reversedAt) return transaction;
  if (transaction.type === 'deposit') {
    const wallet = await Wallet.findOne({ userId: transaction.userId });
    const recoverableCents = Math.min(Math.max(0, wallet?.availableBalanceCents || 0), transaction.amountCents);
    const chargebackCents = transaction.amountCents - recoverableCents;
    await updateWalletBalances(
      transaction.userId,
      {
        availableBalanceCents: -recoverableCents,
        chargebackBalanceCents: chargebackCents,
        lifetimeDepositsCents: -transaction.amountCents,
        lifetimeRefundsCents: transaction.amountCents,
      },
      `Paynow deposit ${transaction.reference} refunded`,
      'reverseCompletedPayment',
      {},
      `${transaction.reference}:refund`
    );
  }
  if (transaction.type === 'subscription') {
    await Subscription.updateOne(
      { _id: transaction.subscriptionId || transaction.metadata?.subscriptionId },
      { $set: { status: 'cancelled', endDate: new Date(), validUntil: new Date(), lastValidityCheckAt: new Date() } }
    );
    await updateWalletBalances(
      transaction.userId,
      { lifetimeSubscriptionFeesCents: -transaction.amountCents, lifetimeRefundsCents: transaction.amountCents },
      `Subscription ${transaction.reference} refunded`,
      'reverseCompletedPayment',
      {},
      `${transaction.reference}:refund`
    );
  }
  if (transaction.type === 'entry-fee') {
    await LeagueEntry.updateOne(
      { _id: transaction.metadata?.leagueEntryId, userId: transaction.userId },
      { $set: { paymentStatus: 'refunded', eligibilityStatus: 'ineligible', eligibilityReason: 'League entry payment was refunded.' } }
    );
    await updateWalletBalances(
      transaction.userId,
      { lifetimeEntryFeesCents: -transaction.amountCents, lifetimeRefundsCents: transaction.amountCents },
      `League entry ${transaction.reference} refunded`,
      'reverseCompletedPayment',
      {},
      `${transaction.reference}:refund`
    );
  }
  const reversedTransaction = await Transaction.findByIdAndUpdate(
    transaction._id,
    { $set: { status: 'reversed', 'metadata.reversedAt': new Date(), 'metadata.paynowStatus': paynowData.status || 'Refunded' } },
    { new: true }
  );
  await emailService.notifyPaymentUpdate(reversedTransaction);
  return reversedTransaction;
}

async function processPaynowStatus(transaction, paynowData) {
  if (!transaction || !paynowData) return transaction;
  if (transaction.status === 'completed' && !paynowStatusIsRefunded(paynowData.status)) return transaction;
  const responseReference = String(paynowData.reference || '');
  if (responseReference && responseReference !== transaction.reference) {
    const error = new Error('Paynow returned a mismatched merchant reference.');
    error.status = 502;
    throw error;
  }
  if (paynowData.amount) {
    const responseAmountCents = Math.round(Number(paynowData.amount) * 100);
    if (Number.isFinite(responseAmountCents) && responseAmountCents !== transaction.amountCents) {
      const error = new Error('Paynow returned a mismatched payment amount.');
      error.status = 502;
      throw error;
    }
  }
  if (paynowStatusIsPaid(paynowData.status)) return finalizeSuccessfulPayment(transaction, paynowData);
  if (paynowStatusIsRefunded(paynowData.status)) return reverseCompletedPayment(transaction, paynowData);
  if (paynowStatusIsTerminalFailure(paynowData.status)) {
    if (transaction.type === 'deposit') return releasePendingDeposit(transaction, paynowData.status || 'Cancelled', 'cancelled');
    if (transaction.type === 'subscription') {
      await Subscription.updateOne(
        { _id: transaction.subscriptionId || transaction.metadata?.subscriptionId },
        { $set: { status: 'payment-failed', lastValidityCheckAt: new Date() } }
      );
    }
    if (transaction.type === 'entry-fee') {
      await LeagueEntry.updateOne(
        { _id: transaction.metadata?.leagueEntryId, userId: transaction.userId },
        { $set: { paymentStatus: 'failed', paymentReference: transaction.reference } }
      );
    }
    const failedTransaction = await Transaction.findByIdAndUpdate(
      transaction._id,
      { $set: { status: 'rejected', 'metadata.paynowStatus': paynowData.status || 'Failed' } },
      { new: true }
    );
    await emailService.notifyPaymentUpdate(failedTransaction);
    return failedTransaction;
  }
  const processingTransaction = await Transaction.findByIdAndUpdate(
    transaction._id,
    {
      $set: {
        status: 'processing',
        providerReference: paynowData.paynowreference || transaction.providerReference || '',
        'metadata.paynowStatus': paynowData.status || transaction.metadata?.paynowStatus || 'Created',
        'metadata.pollUrl': paynowData.pollurl || transaction.metadata?.pollUrl || '',
      },
    },
    { new: true }
  );
  await emailService.notifyPaymentUpdate(processingTransaction);
  return processingTransaction;
}

async function reconcilePendingPaynowPayments() {
  if (!PAYNOW_PAYMENTS) return;
  // Reconcile every unresolved Paynow checkout, including transactions older than 48 hours.
  // The previous age filter could leave an abandoned checkout permanently blocking wallet payment.
  const transactions = await Transaction.find({
    provider: 'paynow',
    status: { $in: ['pending', 'processing'] },
    'metadata.pollUrl': { $exists: true, $ne: '' },
  }).sort({ updatedAt: 1 }).limit(50);
  for (const transaction of transactions) {
    try {
      const status = await pollPaynowTransaction(transaction);
      if (status) await processPaynowStatus(transaction, status);
    } catch (error) {
      console.error('Paynow reconciliation failed', transaction.reference, error.message);
    }
  }
}

async function resolvePaynowBlockerBeforeWalletPurchase({ userId, type, planCode = '', leagueId = null }) {
  const query = {
    userId,
    type,
    provider: { $in: ['paynow', 'mock'] },
    status: { $in: ['pending', 'processing'] },
  };
  if (planCode) query['metadata.planCode'] = planCode;
  if (leagueId) query.leagueId = leagueId;

  const candidates = await Transaction.find(query).sort({ createdAt: 1 }).limit(10);
  for (let transaction of candidates) {
    // Before blocking a wallet purchase, refresh the provider state synchronously.
    // This clears checkouts that Paynow has already marked failed/cancelled and avoids
    // making the user wait for the maintenance job.
    if (
      transaction.provider === 'paynow'
      && PAYNOW_PAYMENTS
      && transaction.metadata?.pollUrl
      && ['pending', 'processing'].includes(transaction.status)
    ) {
      try {
        const status = await pollPaynowTransaction(transaction);
        if (status) transaction = await processPaynowStatus(transaction, status);
      } catch (error) {
        console.error('Paynow blocker refresh failed', transaction.reference, error.message);
        transaction = await Transaction.findById(transaction._id);
      }
    }

    if (!transaction) continue;
    if (transaction.status === 'completed') return { state: 'completed', transaction };
    if (['pending', 'processing'].includes(transaction.status)) return { state: 'pending', transaction };
  }
  return null;
}

async function getEarningsLeaderboard(currentUserId, limit = 10) {
  const aggregates = await Transaction.aggregate([
    { $match: { type: 'prize', status: 'completed', direction: 'credit' } },
    {
      $group: {
        _id: '$userId',
        earningsCents: { $sum: '$amountCents' },
        wins: { $sum: 1 },
        lastWinAt: { $max: '$createdAt' },
      },
    },
    { $sort: { wins: -1, earningsCents: -1, lastWinAt: 1 } },
    { $limit: limit },
  ]);

  const ids = aggregates.map((item) => item._id);
  const [users, profiles] = await Promise.all([
    User.find({ _id: { $in: ids } }).select('fullName').lean(),
    UserProfile.find({ userId: { $in: ids } }).select('userId profilePicture').lean(),
  ]);
  const userMap = new Map(users.map((user) => [String(user._id), user]));
  const profileMap = new Map(profiles.map((profile) => [String(profile.userId), profile]));

  return aggregates.map((item, index) => ({
    rank: index + 1,
    userId: String(item._id),
    name: userMap.get(String(item._id))?.fullName || 'Supreme Player',
    profilePicture: profileMap.get(String(item._id))?.profilePicture || '',
    earningsCents: item.earningsCents,
    wins: item.wins,
    lastWinAt: item.lastWinAt,
    isCurrentUser: String(item._id) === String(currentUserId),
  }));
}

async function leagueView(league, userId = null) {
  // Keep list/detail reads DB-only and parallel. Live FPL work is deliberately
  // handled by the page's automatic refresh request after cached content renders.
  const [participantCount, reservedCount, entry, accessPolicy] = await Promise.all([
    LeagueEntry.countDocuments({ leagueId: league._id, paymentStatus: 'paid' }),
    LeagueEntry.countDocuments({ leagueId: league._id, paymentStatus: { $in: ['paid', 'pending'] } }),
    userId ? LeagueEntry.findOne({ leagueId: league._id, userId }).lean() : Promise.resolve(null),
    localGrowth.getLeagueAccessPolicy(league._id),
  ]);
  const grossPoolCents = participantCount * league.entryFeeCents;
  const platformFeeCents = league.customLeague ? Math.round(grossPoolCents * league.platformFeeBasisPoints / 10000) : 0;
  const projectedPrizeCents = league.customLeague ? grossPoolCents - platformFeeCents : league.projectedPrizeCents;
  const createdByCurrentUser = Boolean(userId && String(league.createdBy || '') === String(userId));
  const joined = entry?.paymentStatus === 'paid';
  return {
    id: league._id,
    name: league.name,
    description: league.description,
    competitionType: league.competitionType,
    cadence: league.cadence,
    officialSupremeLeague: league.officialSupremeLeague,
    customLeague: league.customLeague,
    inviteOnly: league.inviteOnly,
    visibility: accessPolicy?.visibility || (league.inviteOnly ? 'private' : 'public'),
    joinDeadlineAt: accessPolicy?.joinDeadlineAt || league.fplJoinDeadlineAt || null,
    allowLateJoin: accessPolicy?.allowLateJoin !== false,
    inviteCode: createdByCurrentUser ? league.inviteCode : '',
    createdByCurrentUser,
    status: league.status,
    startGameweek: league.startGameweek,
    endGameweek: league.endGameweek,
    currentGameweek: league.currentGameweek,
    entryFeeCents: league.entryFeeCents,
    participantCount,
    reservedCount,
    grossPoolCents,
    platformFeeCents,
    projectedPrizeCents,
    displayedPrizeCents: league.displayedPrizeCents,
    guaranteedPrize: league.guaranteedPrize,
    prizeType: league.prizeType,
    minimumParticipants: league.minimumParticipants,
    maximumParticipants: league.maximumParticipants,
    tieBreak: league.tieBreak,
    rules: league.rules,
    createdAt: league.createdAt,
    updatedAt: league.updatedAt,
    expiresAt: league.expiresAt,
    fplJoinDeadlineAt: league.fplJoinDeadlineAt,
    fplLastFixtureKickoffAt: league.fplLastFixtureKickoffAt,
    fplFinishedAt: league.fplFinishedAt,
    fplDataCheckedAt: league.fplDataCheckedAt,
    completedAt: league.completedAt,
    archivedAt: league.archivedAt,
    lastScoredAt: league.lastScoredAt,
    scoreThroughGameweek: league.scoreThroughGameweek,
    scoreSyncStatus: league.scoreSyncStatus,
    scoreSyncMessage: league.scoreSyncMessage,
    isPast: leagueIsPast(league),
    joined,
    entry,
    canPayEntry: Boolean(entry && entry.paymentStatus !== 'paid' && !leagueIsPast(league) && ['draft', 'open', 'upcoming'].includes(league.status)),
  };
}

// -----------------------------------------------------------------------------
// Public endpoints
// -----------------------------------------------------------------------------
app.get('/api/health', (req, res) => success(res, {
  status: 'ok',
  environment: process.env.NODE_ENV || 'development',
  paymentMode: PAYMENTS_MODE,
  mockPayments: MOCK_PAYMENTS,
  paynowConfigured: PAYNOW_PAYMENTS && Boolean(PAYNOW_INTEGRATION_ID && PAYNOW_INTEGRATION_KEY),
  paynowTestMode: PAYNOW_TEST_MODE,
  mockFantasyData: MOCK_FANTASY,
  realMoneyEnabled: process.env.REAL_MONEY_ENABLED === 'true',
}));


app.get('/api/public/marketing-metrics', async (req, res, next) => {
  try {
    const now = new Date();
    const activeSubscriberIds = await Subscription.distinct('userId', {
      status: 'active',
      $or: [
        { validUntil: { $gt: now } },
        { validUntil: null, endDate: { $gt: now } },
        { validUntil: null, endDate: null, renewalDate: { $gt: now } },
      ],
    });
    const activeSubscribers = activeSubscriberIds.length;
    const monthlyPrizeRoadmap = PUBLIC_MONTHLY_PRIZE_ROADMAP.map((item) => ({
      ...item,
      reached: activeSubscribers >= item.activeSubscribers,
      additionalPrizeCents: Math.max(0, item.totalPrizeCents - PUBLIC_PRIZE_SCHEDULE.monthly),
    }));
    const nextMilestone = monthlyPrizeRoadmap.find((item) => item.activeSubscribers > activeSubscribers) || null;
    const reachedMilestones = monthlyPrizeRoadmap.filter((item) => item.activeSubscribers <= activeSubscribers);
    const previousThreshold = reachedMilestones.length
      ? reachedMilestones[reachedMilestones.length - 1].activeSubscribers
      : 0;
    const progressPercent = nextMilestone
      ? Math.max(0, Math.min(100, Math.round(
          ((activeSubscribers - previousThreshold) / Math.max(1, nextMilestone.activeSubscribers - previousThreshold)) * 100
        )))
      : 100;

    const illustrativeSeasonPath = [
      { label: '4 weekly wins', count: 4, unitPrizeCents: PUBLIC_PRIZE_SCHEDULE.weekly, totalCents: PUBLIC_PRIZE_SCHEDULE.weekly * 4 },
      { label: '2 bi-weekly wins', count: 2, unitPrizeCents: PUBLIC_PRIZE_SCHEDULE.biWeekly, totalCents: PUBLIC_PRIZE_SCHEDULE.biWeekly * 2 },
      { label: '1 monthly win', count: 1, unitPrizeCents: PUBLIC_PRIZE_SCHEDULE.monthly, totalCents: PUBLIC_PRIZE_SCHEDULE.monthly },
      { label: '1 half-season win', count: 1, unitPrizeCents: PUBLIC_PRIZE_SCHEDULE.halfSeason, totalCents: PUBLIC_PRIZE_SCHEDULE.halfSeason },
      { label: 'Season title', count: 1, unitPrizeCents: PUBLIC_PRIZE_SCHEDULE.season, totalCents: PUBLIC_PRIZE_SCHEDULE.season },
    ];

    return success(res, {
      activeSubscribers,
      prizeSchedule: PUBLIC_PRIZE_SCHEDULE,
      referralRewardCents: nonNegativeIntegerFromEnv('REFERRAL_REWARD_CENTS', 100),
      monthlyPrizeRoadmap,
      nextMilestone,
      progressPercent,
      plans: Object.values(PLANS).map((plan) => ({
        planCode: plan.planCode,
        planName: plan.planName,
        amountCents: plan.amountCents,
        billingInterval: plan.billingInterval,
      })),
      illustrativeSeasonPath,
      illustrativeSeasonPathTotalCents: illustrativeSeasonPath.reduce((total, item) => total + item.totalCents, 0),
      updatedAt: now.toISOString(),
      disclosure: 'Roadmap figures are planned promotional targets. A prize becomes binding only when marked confirmed for a specific competition before entry.',
    });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/waitlist', writeLimiter, async (req, res, next) => {
  try {
    const { fullName, email, phone, ageConfirmed, marketingConsent } = req.body;
    if (!fullName || !email || !phone || ageConfirmed !== true) return failure(res, 400, 'Complete all required waitlist fields and confirm you are 18 or older.');
    const normalized = normalizeEmail(email);
    const existing = await WaitlistEntry.findOne({ email: normalized });
    if (existing) return failure(res, 409, 'This email is already on the waitlist.');
    const entry = await WaitlistEntry.create({ fullName, email: normalized, phone, ageConfirmed, marketingConsent: Boolean(marketingConsent) });
    return success(res, { id: entry._id, message: 'You are on the Supreme Fantasy League waitlist.' }, 201);
  } catch (error) { next(error); }
});

app.post('/api/auth/register', authLimiter, async (req, res, next) => {
  try {
    const { fullName, email, phone, dateOfBirth, password, confirmPassword, ageConfirmed, termsAccepted, privacyAccepted, rulesAccepted, securityAcknowledged } = req.body;
    const errors = [];
    if (!fullName || fullName.trim().length < 2) errors.push('Enter your full name.');
    if (!/^\+?263\d{9}$/.test(String(phone || '').replace(/\s/g, ''))) errors.push('Enter a valid Zimbabwe phone number, for example +263771234567.');
    if (!isAdult(dateOfBirth) || ageConfirmed !== true) errors.push('You must be at least 18 years old.');
    if (!password || password.length < 8) errors.push('Password must be at least 8 characters.');
    if (password !== confirmPassword) errors.push('Passwords do not match.');
    if (!termsAccepted || !privacyAccepted || !rulesAccepted || !securityAcknowledged) errors.push('Terms, Privacy, Competition Rules and the account-security acknowledgement are required.');
    if (errors.length) return failure(res, 400, 'Registration validation failed.', errors);

    const normalized = normalizeEmail(email);
    if (!/^\S+@\S+\.\S+$/.test(normalized)) return failure(res, 400, 'Enter a valid email address.');
    if (await User.exists({ email: normalized })) return failure(res, 409, 'An account with this email already exists.');

    const referralCode = String(req.body.referralCode || '')
      .trim()
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, '');
    if (referralCode) {
      const referralExists = await localGrowth.models.ReferralAccount.exists({ code: referralCode });
      if (!referralExists) return failure(res, 400, 'The referral code is not valid. Check the code and try again.');
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const acceptedAt = new Date();
    const user = await User.create({
      fullName,
      email: normalized,
      phone,
      dateOfBirth,
      passwordHash,
      ageConfirmed: true,
      legalAcceptance: {
        termsVersion: LEGAL_TERMS_VERSION,
        privacyVersion: LEGAL_PRIVACY_VERSION,
        rulesVersion: LEGAL_RULES_VERSION,
        effectiveDate: LEGAL_EFFECTIVE_DATE,
        acceptedAt,
        securityAcknowledgedAt: acceptedAt,
        ipHash: crypto.createHash('sha256').update(`${req.ip || ''}|${process.env.JWT_SECRET}`).digest('hex'),
        userAgent: String(req.headers['user-agent'] || '').slice(0, 250),
      },
    });
    const { profile } = await ensureUserResources(user._id);
    const token = signToken(user);
    setSessionCookie(res, token);
    await logAudit(req, 'auth.register', 'User', user._id, null, { email: user.email, termsVersion: LEGAL_TERMS_VERSION, privacyVersion: LEGAL_PRIVACY_VERSION, rulesVersion: LEGAL_RULES_VERSION }, 'User registration and legal acceptance');
    await Promise.all([emailService.notifyWelcome(user), emailService.notifyOwnerUserSignup(user)]);
    await localGrowth.ensureReferralAccount(user, referralCode);
    return success(res, { user: publicUser(user, profile) }, 201);
  } catch (error) { next(error); }
});

app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const user = await User.findOne({ email }).select('+passwordHash');
    if (!user || !(await bcrypt.compare(req.body.password || '', user.passwordHash))) return failure(res, 401, 'Invalid email or password.');
    if (user.status !== 'active') return failure(res, 403, 'This account is not active.');
    const profile = await UserProfile.findOne({ userId: user._id });
    setSessionCookie(res, signToken(user));
    return success(res, { user: publicUser(user, profile) });
  } catch (error) { next(error); }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: IS_PRODUCTION, sameSite: IS_PRODUCTION ? 'none' : 'lax', path: '/' });
  return success(res, { message: 'Logged out.' });
});

app.get('/api/auth/me', requireAuth, async (req, res, next) => {
  try {
    const profile = await UserProfile.findOne({ userId: req.user._id });
    return success(res, { user: publicUser(req.user, profile) });
  } catch (error) { next(error); }
});

app.post('/api/auth/accept-legal', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    if (req.user.role !== 'user') return failure(res, 403, 'Legal acceptance is managed through the user account flow.');
    const { ageConfirmed, termsAccepted, privacyAccepted, rulesAccepted, securityAcknowledged } = req.body || {};
    if (![ageConfirmed, termsAccepted, privacyAccepted, rulesAccepted, securityAcknowledged].every((value) => value === true)) {
      return failure(res, 400, 'Confirm every required legal and security acknowledgement.');
    }
    const acceptedAt = new Date();
    req.user.ageConfirmed = true;
    req.user.legalAcceptance = {
      termsVersion: LEGAL_TERMS_VERSION,
      privacyVersion: LEGAL_PRIVACY_VERSION,
      rulesVersion: LEGAL_RULES_VERSION,
      effectiveDate: LEGAL_EFFECTIVE_DATE,
      acceptedAt,
      securityAcknowledgedAt: acceptedAt,
      ipHash: crypto.createHash('sha256').update(`${req.ip || ''}|${process.env.JWT_SECRET}`).digest('hex'),
      userAgent: String(req.headers['user-agent'] || '').slice(0, 250),
    };
    await req.user.save();
    await logAudit(req, 'auth.legal.accepted', 'User', req.user._id, null, {
      termsVersion: LEGAL_TERMS_VERSION,
      privacyVersion: LEGAL_PRIVACY_VERSION,
      rulesVersion: LEGAL_RULES_VERSION,
    }, 'User accepted current legal documents');
    const profile = await UserProfile.findOne({ userId: req.user._id });
    return success(res, { user: publicUser(req.user, profile), message: 'Your acceptance has been recorded.' });
  } catch (error) { next(error); }
});

// -----------------------------------------------------------------------------
// Profile endpoints
// -----------------------------------------------------------------------------
app.get('/api/profile', requireAuth, async (req, res, next) => {
  try {
    const { profile } = await ensureUserResources(req.user._id);
    const subscription = await currentSubscription(req.user._id);
    return success(res, { user: publicUser(req.user, profile), profile, subscription });
  } catch (error) { next(error); }
});

app.put('/api/profile', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    const { fullName, phone, dateOfBirth, city, address, country, currency, contactPreference, notificationPreferences } = req.body;
    if (dateOfBirth && !isAdult(dateOfBirth)) return failure(res, 400, 'The account holder must be at least 18 years old.');

    const beforeUser = publicUser(req.user);
    if (fullName) req.user.fullName = String(fullName).trim();
    if (phone) req.user.phone = String(phone).trim();
    if (dateOfBirth) req.user.dateOfBirth = new Date(dateOfBirth);
    if (country) req.user.country = country;
    if (currency) req.user.currency = currency;
    await req.user.save();

    const currentProfile = await UserProfile.findOne({ userId: req.user._id }).lean();
    const completionPicture = currentProfile?.profilePicture || '';
    const profile = await UserProfile.findOneAndUpdate(
      { userId: req.user._id },
      {
        $set: {
          ...(city !== undefined ? { city } : {}),
          ...(address !== undefined ? { address } : {}),
          ...(contactPreference ? { contactPreference } : {}),
          ...(notificationPreferences ? { notificationPreferences } : {}),
          profileCompletion: clamp([
            req.user.fullName,
            req.user.email,
            req.user.phone,
            city ?? currentProfile?.city,
            address ?? currentProfile?.address,
            req.user.fplManagerId,
            completionPicture,
          ].filter(Boolean).length * 14, 20, 100),
        },
        $setOnInsert: { userId: req.user._id },
      },
      { upsert: true, new: true }
    );
    await logAudit(req, 'profile.update', 'User', req.user._id, beforeUser, publicUser(req.user, profile), 'User profile update');
    return success(res, { user: publicUser(req.user, profile), profile });
  } catch (error) { next(error); }
});

app.post('/api/profile/picture', requireAuth, writeLimiter, async (req, res) => {
  const parsed = parseProfileImageDataUrl(req.body?.image);
  if (!parsed.ok) return failure(res, 400, parsed.message);

  try {
    const previousProfile = await UserProfile.findOne({ userId: req.user._id }).lean();
    const uploaded = await uploadProfilePictureToCloudinary(req.user._id, parsed);
    if (!uploaded.secure_url || !uploaded.public_id || uploaded.resource_type !== 'image') {
      return failure(res, 502, 'Cloudinary accepted the request but did not return a renderable image URL.');
    }

    const profile = await UserProfile.findOneAndUpdate(
      { userId: req.user._id },
      {
        $set: {
          profilePicture: uploaded.secure_url,
          profilePicturePublicId: uploaded.public_id,
          profilePictureFormat: uploaded.format || parsed.extension,
          profilePictureBytes: Number(uploaded.bytes || parsed.buffer.length),
          profilePictureUpdatedAt: new Date(),
          profileCompletion: clamp([
            req.user.fullName,
            req.user.email,
            req.user.phone,
            previousProfile?.city,
            previousProfile?.address,
            req.user.fplManagerId,
            uploaded.secure_url,
          ].filter(Boolean).length * 14, 20, 100),
        },
        $setOnInsert: { userId: req.user._id },
      },
      { upsert: true, new: true }
    );

    if (previousProfile?.profilePicturePublicId
      && previousProfile.profilePicturePublicId !== uploaded.public_id) {
      removeProfilePictureFromCloudinary(previousProfile.profilePicturePublicId).catch((error) => {
        console.warn('Unable to remove the previous Cloudinary profile picture:', error.message);
      });
    }

    await logAudit(
      req,
      'profile.picture.upload',
      'UserProfile',
      profile._id,
      { profilePicture: previousProfile?.profilePicture || '' },
      { profilePicture: profile.profilePicture, profilePicturePublicId: profile.profilePicturePublicId },
      'Cloudinary profile picture upload'
    );

    return success(res, {
      message: 'Profile picture uploaded successfully.',
      user: publicUser(req.user, profile),
      profile,
    }, 201);
  } catch (error) {
    const reason = cloudinaryPublicErrorMessage(error);
    return failure(res, Number(error.status || 502), `The image could not be uploaded: ${reason}`);
  }
});

app.delete('/api/profile/picture', requireAuth, writeLimiter, async (req, res) => {
  try {
    const existing = await UserProfile.findOne({ userId: req.user._id });
    if (!existing?.profilePicture) {
      return success(res, {
        message: 'There is no profile picture to remove.',
        user: publicUser(req.user, existing),
        profile: existing,
      });
    }

    if (existing.profilePicturePublicId) {
      const removal = await removeProfilePictureFromCloudinary(existing.profilePicturePublicId);
      if (!['ok', 'not found', 'skipped-no-signed-credentials'].includes(String(removal.result || '').toLowerCase())) {
        return failure(res, 502, `Cloudinary could not remove the image: ${removal.result || 'unknown response'}.`);
      }
    }

    const beforePicture = existing.profilePicture;
    existing.profilePicture = '';
    existing.profilePicturePublicId = '';
    existing.profilePictureFormat = '';
    existing.profilePictureBytes = 0;
    existing.profilePictureUpdatedAt = null;
    existing.profileCompletion = clamp([
      req.user.fullName,
      req.user.email,
      req.user.phone,
      existing.city,
      existing.address,
      req.user.fplManagerId,
    ].filter(Boolean).length * 14, 20, 100);
    await existing.save();

    await logAudit(
      req,
      'profile.picture.remove',
      'UserProfile',
      existing._id,
      { profilePicture: beforePicture },
      { profilePicture: '' },
      'Cloudinary profile picture removal'
    );

    return success(res, {
      message: 'Profile picture removed.',
      user: publicUser(req.user, existing),
      profile: existing,
    });
  } catch (error) {
    const reason = cloudinaryPublicErrorMessage(error);
    return failure(res, Number(error.status || 502), `The image could not be removed: ${reason}`);
  }
});

app.post('/api/profile/link-fantasy-team', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    const managerId = String(req.body.managerId || '').trim();
    if (!/^\d+$/.test(managerId)) return failure(res, 400, 'Fantasy manager ID must contain numbers only.');
    const manager = await fantasyProvider.getManager(managerId);
    await linkFantasyManagerToUser(req.user, managerId, manager.teamName);
    const snapshot = await persistFantasyTeamSnapshot(req.user, { force: true }).catch((error) => ({ error: error.message }));
    const enrollment = await localGrowth.enrollUserInOpenSupremeLeagues(req.user._id).catch((error) => ({ enrolled: 0, error: error.message }));
    return success(res, { manager, snapshot, enrollment });
  } catch (error) { next(error); }
});

// -----------------------------------------------------------------------------
// Authenticated public player profiles
// -----------------------------------------------------------------------------
app.get('/api/users/:userId/public-profile', requireAuth, async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.userId)) {
      return failure(res, 404, 'Player profile not found.');
    }

    const userId = new mongoose.Types.ObjectId(req.params.userId);
    const [user, profile, winStats] = await Promise.all([
      User.findById(userId)
        .select('fullName fantasyTeamName fplManagerId status createdAt')
        .lean(),
      UserProfile.findOne({ userId })
        .select('profilePicture')
        .lean(),
      Transaction.aggregate([
        {
          $match: {
            userId,
            type: 'prize',
            direction: 'credit',
            status: 'completed',
          },
        },
        {
          $group: {
            _id: '$userId',
            wins: { $sum: 1 },
            prizeEarningsCents: { $sum: '$amountCents' },
            lastWinAt: { $max: '$createdAt' },
          },
        },
      ]),
    ]);

    if (!user || user.status === 'closed') {
      return failure(res, 404, 'Player profile not found.');
    }

    let snapshot = await TeamSnapshot.findOne({ userId, syncStatus: 'success' })
      .sort({ fetchedAt: -1, createdAt: -1 })
      .select('gameweek teamName managerName gameweekPoints totalPoints overallRank gameweekRank teamValue bank captain viceCaptain activeChip lineup fetchedAt lastSuccessfulSyncAt')
      .lean();
    let refreshWarning = '';
    const refreshRequested = String(req.query.refresh || '') === '1';
    if (user.fplManagerId && refreshRequested) {
      try {
        const refreshed = await persistFantasyTeamSnapshot(user, { force: false });
        snapshot = refreshed.snapshot?.toObject ? refreshed.snapshot.toObject() : refreshed.snapshot || snapshot;
      } catch (error) {
        refreshWarning = String(error.message || error);
      }
    }

    const results = winStats[0] || {};
    return success(res, {
      profile: {
        userId: String(user._id),
        name: user.fullName,
        profilePicture: profile?.profilePicture || '',
        fantasyTeamName: snapshot?.teamName || user.fantasyTeamName || '',
        memberSince: user.createdAt,
        wins: Number(results.wins || 0),
        prizeEarningsCents: Number(results.prizeEarningsCents || 0),
        lastWinAt: results.lastWinAt || null,
        fpl: {
          linked: Boolean(user.fplManagerId),
          hasSnapshot: Boolean(snapshot),
          managerName: snapshot?.managerName || '',
          gameweek: snapshot?.gameweek ?? null,
          gameweekPoints: snapshot?.gameweekPoints ?? null,
          totalPoints: snapshot?.totalPoints ?? null,
          overallRank: snapshot?.overallRank ?? null,
          gameweekRank: snapshot?.gameweekRank ?? null,
          teamValue: snapshot?.teamValue ?? null,
          bank: snapshot?.bank ?? null,
          captain: snapshot?.captain || '',
          viceCaptain: snapshot?.viceCaptain || '',
          activeChip: snapshot?.activeChip || 'None',
          lineup: snapshot?.lineup || [],
          lastSyncedAt: snapshot?.lastSuccessfulSyncAt || snapshot?.fetchedAt || null,
          refreshWarning,
        },
      },
    });
  } catch (error) { next(error); }
});

// -----------------------------------------------------------------------------
// Team endpoints
// -----------------------------------------------------------------------------
function leagueIsPast(league, now = new Date()) {
  if (!league) return false;
  if (['awaiting-review', 'settled', 'cancelled'].includes(league.status)) return true;
  if (league.fplFinishedAt) return true;
  // Keep the legacy timestamp check for records that have not yet been corrected.
  return Boolean(league.expiresAt && new Date(league.expiresAt) <= now);
}

function fplEventFromBootstrap(bootstrap, gameweek) {
  const events = Array.isArray(bootstrap?.events) ? bootstrap.events : [];
  return events.find((event) => Number(event.id) === Number(gameweek)) || null;
}

function latestFixtureKickoff(fixtures = []) {
  const timestamps = (Array.isArray(fixtures) ? fixtures : [])
    .map((fixture) => new Date(fixture?.kickoff_time || ''))
    .filter((value) => !Number.isNaN(value.getTime()))
    .sort((a, b) => b.getTime() - a.getTime());
  return timestamps[0] || null;
}

async function getFplGameweekSchedule(gameweek, { bootstrap = null, includeFixtures = true } = {}) {
  const eventId = Number(gameweek);
  if (!Number.isInteger(eventId) || eventId < 1) {
    const error = new Error('A valid FPL gameweek is required.');
    error.status = 400;
    throw error;
  }
  if (FPL_DATA_MODE !== 'public') {
    return {
      gameweek: eventId,
      deadlineAt: null,
      lastFixtureKickoffAt: null,
      finished: false,
      dataChecked: false,
      providerMode: FPL_DATA_MODE,
    };
  }

  const bootstrapData = bootstrap || await publicFantasyProvider.getBootstrap();
  const event = fplEventFromBootstrap(bootstrapData, eventId);
  if (!event) {
    const error = new Error(`FPL Gameweek ${eventId} is not available in bootstrap-static.`);
    error.status = 409;
    throw error;
  }

  let lastFixtureKickoffAt = null;
  let fixtureCount = 0;
  let fixturesFinished = null;
  let hasProvisionalOnlyFixtures = false;
  if (includeFixtures) {
    const fixtures = await fetchFplJson(`/fixtures/?event=${eventId}`, { cacheMinutes: Math.min(FPL_CACHE_MINUTES, 2) });
    fixtureCount = Array.isArray(fixtures) ? fixtures.length : 0;
    lastFixtureKickoffAt = latestFixtureKickoff(fixtures);
    fixturesFinished = fixtureCount > 0 && fixtures.every((fixture) => fixture?.finished === true);
    hasProvisionalOnlyFixtures = fixtureCount > 0 && fixtures.some(
      (fixture) => fixture?.finished !== true && fixture?.finished_provisional === true
    );
  }

  const deadlineAt = event.deadline_time ? new Date(event.deadline_time) : null;
  const eventFinished = event.finished === true;
  const footballFinished = includeFixtures ? Boolean(eventFinished && fixturesFinished) : eventFinished;
  return {
    gameweek: eventId,
    deadlineAt: deadlineAt && !Number.isNaN(deadlineAt.getTime()) ? deadlineAt : null,
    lastFixtureKickoffAt,
    eventFinished,
    fixturesFinished,
    fixtureCount,
    hasProvisionalOnlyFixtures,
    finished: footballFinished,
    dataChecked: event.data_checked === true,
    isCurrent: event.is_current === true,
    isNext: event.is_next === true,
    isPrevious: event.is_previous === true,
    providerMode: 'public',
  };
}

async function getVerifiedFplRangeState(startGameweek, endGameweek, { bootstrap = null } = {}) {
  if (FPL_DATA_MODE !== 'public') {
    return { finished: false, dataChecked: false, events: [], schedules: [], reason: 'provider-not-public' };
  }
  const bootstrapData = bootstrap || await publicFantasyProvider.getBootstrap({ cacheMinutes: 1 });
  const start = Number(startGameweek);
  const end = Number(endGameweek);
  const events = (bootstrapData.events || []).filter((event) => Number(event.id) >= start && Number(event.id) <= end);
  if (!events.length || events.length !== end - start + 1) {
    return { finished: false, dataChecked: false, events, schedules: [], reason: 'missing-events' };
  }
  const schedules = [];
  for (const event of events) {
    schedules.push(await getFplGameweekSchedule(event.id, { bootstrap: bootstrapData, includeFixtures: true }));
  }
  const finished = schedules.every((schedule) => schedule.eventFinished === true && schedule.fixturesFinished === true);
  const dataChecked = finished && events.every((event) => event.data_checked === true);
  return {
    finished,
    dataChecked,
    events,
    schedules,
    reason: finished ? (dataChecked ? 'final' : 'awaiting-data-check') : 'football-not-finished',
    lastFixtureKickoffAt: schedules.map((item) => item.lastFixtureKickoffAt).filter(Boolean).sort((a, b) => b - a)[0] || null,
  };
}

async function applyFplLifecycleToLeague(league, bootstrap, now = new Date(), { includeFixtures = true } = {}) {
  if (!league || FPL_DATA_MODE !== 'public') return false;
  const startEvent = fplEventFromBootstrap(bootstrap, league.startGameweek);
  const endEvent = fplEventFromBootstrap(bootstrap, league.endGameweek);
  if (!startEvent || !endEvent) return false;

  const startDeadlineAt = startEvent.deadline_time ? new Date(startEvent.deadline_time) : null;
  if (startDeadlineAt && !Number.isNaN(startDeadlineAt.getTime())) {
    league.fplJoinDeadlineAt = startDeadlineAt;
  }

  let endSchedule = null;
  if (includeFixtures) {
    try {
      endSchedule = await getFplGameweekSchedule(league.endGameweek, { bootstrap, includeFixtures: true });
      if (endSchedule.lastFixtureKickoffAt) league.fplLastFixtureKickoffAt = endSchedule.lastFixtureKickoffAt;
    } catch (error) {
      console.warn(`Could not load FPL fixtures for league ${league._id}:`, error.message);
    }
  }

  const footballFinished = includeFixtures
    ? Boolean(endSchedule?.eventFinished === true && endSchedule?.fixturesFinished === true)
    : endEvent.finished === true;

  if (footballFinished) {
    const observedFinishedAt = league.fplFinishedAt || now;
    league.fplFinishedAt = observedFinishedAt;
    league.expiresAt = observedFinishedAt;
    if (['open', 'full', 'upcoming', 'live'].includes(league.status)) {
      league.status = 'awaiting-review';
    }
    league.completedAt = league.completedAt || observedFinishedAt;
  } else if (!['settled', 'cancelled'].includes(league.status)) {
    // Remove the old guessed expiry timestamp. While FPL still says the end
    // gameweek is unfinished, the league must stay active. This also repairs
    // legacy records that were prematurely moved to awaiting-review.
    league.expiresAt = null;
    league.fplFinishedAt = null;
    league.completedAt = null;

    if (league.status === 'awaiting-review') {
      const paidCount = await LeagueEntry.countDocuments({ leagueId: league._id, paymentStatus: 'paid' });
      const maximumParticipants = Number(league.maximumParticipants || 0);
      if (maximumParticipants > 0 && paidCount >= maximumParticipants) league.status = 'full';
      else if (startDeadlineAt && !Number.isNaN(startDeadlineAt.getTime()) && now >= startDeadlineAt) league.status = 'live';
      else league.status = 'open';
    } else if (startDeadlineAt && !Number.isNaN(startDeadlineAt.getTime()) && now >= startDeadlineAt) {
      if (['open', 'upcoming'].includes(league.status)) league.status = 'live';
    }
  }

  if (endEvent.data_checked === true) {
    league.fplDataCheckedAt = league.fplDataCheckedAt || now;
  } else if (!['settled', 'cancelled'].includes(league.status)) {
    league.fplDataCheckedAt = null;
  }

  if (!league.isModified()) return false;
  await league.save();
  return true;
}

async function backfillLeagueEntryFantasyManagerIds(limit = 500) {
  const entries = await LeagueEntry.find({
    $or: [{ fantasyManagerId: '' }, { fantasyManagerId: { $exists: false } }],
  }).limit(limit).populate('userId', 'fplManagerId');
  let updated = 0;
  for (const entry of entries) {
    const managerId = String(entry.userId?.fplManagerId || '').trim();
    if (!managerId) continue;
    entry.fantasyManagerId = managerId;
    await entry.save();
    updated += 1;
  }
  return updated;
}

async function backfillLeagueExpiryDates(limit = 100) {
  if (FPL_DATA_MODE !== 'public') return 0;
  try {
    const bootstrap = await publicFantasyProvider.getBootstrap();
    const leagues = await League.find({
      status: { $nin: ['settled', 'cancelled'] },
    }).sort({ createdAt: 1 }).limit(limit);
    let updated = 0;
    for (const league of leagues) {
      if (await applyFplLifecycleToLeague(league, bootstrap, new Date(), { includeFixtures: true })) updated += 1;
    }
    return updated;
  } catch (error) {
    console.warn('FPL league lifecycle backfill skipped because the provider is unavailable:', error.message);
    return 0;
  }
}

async function updateExpiredLeagueStatuses() {
  if (FPL_DATA_MODE !== 'public') {
    const now = new Date();
    const result = await League.updateMany(
      {
        expiresAt: { $lte: now },
        status: { $in: ['open', 'full', 'upcoming', 'live'] },
      },
      { $set: { status: 'awaiting-review', completedAt: now } }
    );
    return result.modifiedCount || 0;
  }

  try {
    const bootstrap = await publicFantasyProvider.getBootstrap();
    const leagues = await League.find({
      status: { $in: ['open', 'full', 'upcoming', 'live', 'awaiting-review'] },
    });
    let updated = 0;
    const now = new Date();
    for (const league of leagues) {
      if (await applyFplLifecycleToLeague(league, bootstrap, now, { includeFixtures: true })) updated += 1;
    }
    return updated;
  } catch (error) {
    console.warn('FPL league lifecycle update skipped because the provider is unavailable:', error.message);
    return 0;
  }
}

let leagueLifecycleRefreshPromise = null;
let leagueLifecycleRefreshedAt = 0;

async function refreshLeagueLifecycleIfStale(maxAgeMs = 5 * 60 * 1000) {
  if (FPL_DATA_MODE !== 'public') return 0;
  const now = Date.now();
  if (leagueLifecycleRefreshedAt && now - leagueLifecycleRefreshedAt < maxAgeMs) return 0;
  if (leagueLifecycleRefreshPromise) return leagueLifecycleRefreshPromise;

  leagueLifecycleRefreshPromise = updateExpiredLeagueStatuses()
    .then((updated) => {
      leagueLifecycleRefreshedAt = Date.now();
      return updated;
    })
    .catch((error) => {
      console.warn('Opportunistic FPL league lifecycle refresh failed:', error.message);
      return 0;
    })
    .finally(() => {
      leagueLifecycleRefreshPromise = null;
    });
  return leagueLifecycleRefreshPromise;
}

async function scoreManagerForLeague(managerId, league, scoreThroughGameweek) {
  const id = normalizeManagerId(managerId);
  if (league.ruleType === 'captain-vice-score' || league.competitionType === 'clash-captains') {
    const gameweek = Number(league.startGameweek);
    const picks = await fantasyProvider.getManagerPicks(id, gameweek);
    const captain = (picks.lineup || []).find((player) => player.isCaptain);
    const viceCaptain = (picks.lineup || []).find((player) => player.isViceCaptain);
    if (!captain || !viceCaptain) throw new Error(`Captain or vice-captain data is unavailable for FPL manager ${id} in Gameweek ${gameweek}.`);
    return {
      score: Number(captain.points || 0) + Number(viceCaptain.points || 0),
      latestOverallRank: Number(picks.entryHistory?.overall_rank || Number.MAX_SAFE_INTEGER),
      details: {
        scoringMode: 'captain-vice-raw-points',
        gameweek,
        captain: { elementId: captain.elementId, name: captain.name, points: Number(captain.points || 0) },
        viceCaptain: { elementId: viceCaptain.elementId, name: viceCaptain.name, points: Number(viceCaptain.points || 0) },
      },
    };
  }

  const history = await fantasyProvider.getManagerHistory(id);
  const relevant = history.filter((week) => week.gameweek >= league.startGameweek && week.gameweek <= scoreThroughGameweek);
  let score = relevant.reduce((total, week) => total + Number(week.points || 0), 0);
  let latest = relevant.length ? relevant[relevant.length - 1] : null;

  // For a currently active gameweek, picks.entry_history is usually fresher than
  // /history/. Replace that GW's history value with the latest public value.
  if (scoreThroughGameweek >= league.startGameweek && scoreThroughGameweek <= league.endGameweek) {
    try {
      const picks = await fantasyProvider.getManagerPicks(id, scoreThroughGameweek);
      const livePoints = Number(picks.entryHistory?.points);
      if (Number.isFinite(livePoints)) {
        const historyCurrent = relevant.find((week) => Number(week.gameweek) === Number(scoreThroughGameweek));
        score = score - Number(historyCurrent?.points || 0) + livePoints;
        latest = {
          ...(historyCurrent || {}),
          gameweek: scoreThroughGameweek,
          points: livePoints,
          rank: Number(picks.entryHistory?.overall_rank || historyCurrent?.rank || 0),
          gameweekRank: Number(picks.entryHistory?.rank || historyCurrent?.gameweekRank || 0),
        };
      }
    } catch (error) {
      if (![404, 409].includes(Number(error.status || error.providerStatus || 0))) throw error;
    }
  }

  return {
    score,
    latestOverallRank: Number(latest?.rank || Number.MAX_SAFE_INTEGER),
    details: { scoringMode: 'fpl-gameweek-points', scoreThroughGameweek },
  };
}

async function syncLeagueScores(leagueId, { force = false } = {}) {
  const league = await League.findById(leagueId);
  if (!league) {
    const error = new Error('League not found.');
    error.status = 404;
    throw error;
  }

  const freshnessMs = FPL_LEAGUE_SCORE_CACHE_MINUTES * 60 * 1000;
  if (!force && league.lastScoredAt && Date.now() - new Date(league.lastScoredAt).getTime() < freshnessMs) {
    return { league, synced: 0, failed: 0, cached: true, scoreThroughGameweek: league.scoreThroughGameweek };
  }

  league.scoreSyncStatus = 'syncing';
  league.scoreSyncMessage = '';
  await league.save();

  const gameState = await fantasyProvider.getGameState();
  const scoreThroughGameweek = Math.max(
    Number(league.startGameweek),
    Math.min(Number(league.endGameweek), Number(gameState.syncGameweek || gameState.currentGameweek || league.currentGameweek))
  );
  const entries = await LeagueEntry.find({ leagueId: league._id, paymentStatus: 'paid' })
    .populate('userId', 'fullName fplManagerId')
    .sort({ joinedAt: 1 });

  let synced = 0;
  let failed = 0;
  const failures = [];

  for (const entry of entries) {
    const managerId = String(entry.fantasyManagerId || entry.userId?.fplManagerId || '').trim();
    entry.previousRank = entry.currentRank || 0;
    if (!managerId) {
      entry.scoreSyncStatus = 'failed';
      entry.scoreSyncError = 'No FPL manager ID is stored for this league member.';
      entry.lastScoreSyncAt = new Date();
      await entry.save();
      failed += 1;
      failures.push(`${entry.userId?.fullName || 'Member'}: missing manager ID`);
      continue;
    }

    try {
      if (!entry.fantasyManagerId) entry.fantasyManagerId = managerId;
      const scoreResult = await scoreManagerForLeague(managerId, league, scoreThroughGameweek);
      entry.currentScore = scoreResult.score;
      entry.scoreThroughGameweek = scoreThroughGameweek;
      entry.latestOverallRank = scoreResult.latestOverallRank;
      entry.scoreDetails = scoreResult.details || {};
      entry.lastScoreSyncAt = new Date();
      entry.scoreSyncStatus = 'success';
      entry.scoreSyncError = '';
      await entry.save();
      synced += 1;
    } catch (error) {
      entry.lastScoreSyncAt = new Date();
      entry.scoreSyncStatus = 'failed';
      entry.scoreSyncError = String(error.message || 'FPL score sync failed.').slice(0, 500);
      await entry.save();
      failed += 1;
      failures.push(`${entry.userId?.fullName || managerId}: ${entry.scoreSyncError}`);
    }
  }

  const rankedEntries = await LeagueEntry.find({ leagueId: league._id, paymentStatus: 'paid' }).sort({
    currentScore: -1,
    latestOverallRank: 1,
    joinedAt: 1,
  });
  for (let index = 0; index < rankedEntries.length; index += 1) {
    rankedEntries[index].currentRank = index + 1;
    await rankedEntries[index].save();
  }

  league.currentGameweek = scoreThroughGameweek;
  league.scoreThroughGameweek = scoreThroughGameweek;
  league.lastScoredAt = new Date();
  league.scoreSyncStatus = failed ? (synced ? 'partial' : 'failed') : 'success';
  league.scoreSyncMessage = failed
    ? `${synced} member(s) synced; ${failed} failed. ${failures.slice(0, 3).join(' | ')}`
    : `${synced} member score(s) synced through Gameweek ${scoreThroughGameweek}.`;
  if (leagueIsPast(league) && ['open', 'full', 'upcoming', 'live'].includes(league.status)) {
    league.status = 'awaiting-review';
    league.completedAt = league.completedAt || new Date();
  }
  await league.save();

  return { league, synced, failed, cached: false, scoreThroughGameweek, failures };
}

async function syncActiveLeagueScores(limit = FPL_LEAGUE_SYNC_LIMIT) {
  const leagues = await League.find({
    status: { $in: ['open', 'full', 'upcoming', 'live', 'awaiting-review'] },
  }).sort({ lastScoredAt: 1, updatedAt: 1 }).limit(limit).select('_id');
  const results = [];
  for (const league of leagues) {
    try {
      results.push(await syncLeagueScores(league._id));
    } catch (error) {
      console.error('League score sync failed', league._id, error.message);
    }
  }
  return results;
}

// Refresh every active linked user's full public FPL squad once per UTC day.
// Manual syncing is no longer part of the normal user workflow. The batch cap is
// only a safety valve for very large installs; page reads still refresh on demand.
async function refreshMemberTeamSnapshots(limit = FPL_TEAM_SNAPSHOT_SYNC_LIMIT) {
  const dayStart = utcDayStart(new Date());
  const users = await User.find({
    role: 'user',
    status: 'active',
    fplManagerId: { $type: 'string', $ne: '' },
  }).select('_id fullName fplManagerId fantasyTeamName').lean();
  if (!users.length) return { checked: 0, refreshed: 0, failed: 0, skippedAlreadyFresh: 0 };

  const latest = await TeamSnapshot.aggregate([
    { $match: { userId: { $in: users.map((user) => user._id) }, syncStatus: 'success' } },
    { $sort: { fetchedAt: -1, updatedAt: -1 } },
    { $group: { _id: '$userId', fetchedAt: { $first: '$fetchedAt' } } },
  ]);
  const latestMap = new Map(latest.map((item) => [String(item._id), item.fetchedAt]));
  const staleUsers = users.filter((user) => !latestMap.get(String(user._id)) || new Date(latestMap.get(String(user._id))) < dayStart);
  const candidates = staleUsers.slice(0, limit);

  let refreshed = 0;
  let failed = 0;
  const concurrency = 4;
  for (let offset = 0; offset < candidates.length; offset += concurrency) {
    const batch = candidates.slice(offset, offset + concurrency);
    const outcomes = await Promise.all(batch.map(async (user) => {
      try {
        await persistFantasyTeamSnapshot(user, { force: true });
        return true;
      } catch (error) {
        console.error('Daily FPL team refresh failed', user._id, error.message);
        return false;
      }
    }));
    refreshed += outcomes.filter(Boolean).length;
    failed += outcomes.filter((value) => !value).length;
  }
  return {
    checked: users.length,
    refreshed,
    failed,
    skippedAlreadyFresh: users.length - staleUsers.length,
    remainingAfterLimit: Math.max(0, staleUsers.length - candidates.length),
  };
}

async function buildTeamPayload(user, { refresh = false } = {}) {
  if (!user.fplManagerId) return { linked: false, providerMode: FPL_DATA_MODE };

  const [latest, lastEntry] = await Promise.all([
    TeamSnapshot.findOne({ userId: user._id }).sort({ fetchedAt: -1 }).lean(),
    LeagueEntry.findOne({ userId: user._id }).sort({ updatedAt: -1 }).lean(),
  ]);

  let providerData = null;
  let providerWarning = '';
  let syncAvailable = true;
  if (refresh) {
    try {
      // Automatic page refreshes respect a short cache. Users still see cached
      // content immediately; stale data is refreshed without a manual button.
      providerData = await persistFantasyTeamSnapshot(user, { force: false });
    } catch (error) {
      syncAvailable = false;
      providerWarning = latest
        ? `${error.message} Showing the last successful automatic refresh instead.`
        : `${error.message} Your FPL account is linked; team data will appear as soon as FPL publishes it.`;
    }
  }

  const refreshedSnapshot = providerData?.snapshot?.toObject ? providerData.snapshot.toObject() : providerData?.snapshot;
  const snapshot = refreshedSnapshot || latest || null;
  let manager = providerData?.manager || null;
  let history = providerData?.history || [];

  // Never make live FPL requests during the fast cached-first render. If this is
  // the follow-up refresh request, manager/history can be completed in parallel.
  if (refresh && (!manager || !history.length)) {
    const [managerResult, historyResult] = await Promise.allSettled([
      manager ? Promise.resolve(manager) : fantasyProvider.getManager(user.fplManagerId),
      history.length ? Promise.resolve(history) : fantasyProvider.getManagerHistory(user.fplManagerId),
    ]);
    if (!manager && managerResult.status === 'fulfilled') manager = managerResult.value;
    if (!history.length && historyResult.status === 'fulfilled') history = historyResult.value;
  }

  manager = manager || {
    managerId: user.fplManagerId,
    teamName: snapshot?.teamName || user.fantasyTeamName || '',
    managerName: snapshot?.managerName || '',
  };

  return {
    linked: true,
    manager,
    history,
    snapshot,
    syncAvailable,
    autoSynced: Boolean(refreshedSnapshot && !providerData?.cached),
    providerMode: FPL_DATA_MODE,
    providerWarning,
    lastConfirmation: lastEntry?.lastConfirmedGameweek || 0,
    inactivityStreak: lastEntry?.consecutiveInactiveGameweeks || 0,
  };
}

app.get('/api/team', requireAuth, async (req, res, next) => {
  try {
    const refresh = String(req.query.refresh || '') === '1';
    return success(res, await buildTeamPayload(req.user, { refresh }));
  } catch (error) { next(error); }
});

app.post('/api/team/sync', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    const managerId = normalizeManagerId(req.body.managerId || req.user.fplManagerId);
    if (managerId !== String(req.user.fplManagerId || '')) {
      const manager = await fantasyProvider.getManager(managerId);
      await linkFantasyManagerToUser(req.user, managerId, manager.teamName);
    }
    const refreshed = await persistFantasyTeamSnapshot(req.user, { force: true });
    return success(res, {
      snapshot: refreshed.snapshot,
      history: refreshed.history,
      manager: refreshed.manager,
      demo: MOCK_FANTASY,
      message: 'Official FPL data refreshed. Team pages now refresh automatically when opened.',
    });
  } catch (error) { next(error); }
});

app.post('/api/team/confirm-gameweek', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    if (!req.user.fplManagerId) return failure(res, 400, 'Link a fantasy manager ID before confirming your team.');
    const game = await fantasyProvider.getGameState();
    const entries = await LeagueEntry.find({ userId: req.user._id });
    for (const entry of entries) {
      entry.lastConfirmedGameweek = game.currentGameweek;
      entry.consecutiveInactiveGameweeks = 0;
      entry.eligibilityStatus = 'eligible';
      entry.eligibilityReason = '';
      await entry.save();
    }
    return success(res, { gameweek: game.currentGameweek, message: 'Team review confirmed for this gameweek.' });
  } catch (error) { next(error); }
});

// -----------------------------------------------------------------------------
// League endpoints
// -----------------------------------------------------------------------------
app.get('/api/fpl/gameweeks', requireAuth, async (req, res, next) => {
  try {
    if (FPL_DATA_MODE !== 'public') {
      return failure(res, 409, 'Live FPL gameweek dates require FPL_DATA_MODE=public.');
    }
    const bootstrap = await publicFantasyProvider.getBootstrap();
    const now = new Date();
    const gameweeks = (Array.isArray(bootstrap.events) ? bootstrap.events : []).map((event) => ({
      id: Number(event.id),
      name: event.name || `Gameweek ${event.id}`,
      deadlineAt: event.deadline_time || null,
      finished: event.finished === true,
      dataChecked: event.data_checked === true,
      isPrevious: event.is_previous === true,
      isCurrent: event.is_current === true,
      isNext: event.is_next === true,
    }));
    const suggested = gameweeks.find((event) => {
      const deadline = event.deadlineAt ? new Date(event.deadlineAt) : null;
      return deadline && !Number.isNaN(deadline.getTime()) && deadline > now;
    }) || null;
    return success(res, {
      source: 'fpl-bootstrap-static',
      fetchedAt: now.toISOString(),
      suggestedStartGameweek: suggested?.id || null,
      gameweeks,
    });
  } catch (error) { next(error); }
});

app.get('/api/leagues', requireAuth, async (req, res, next) => {
  try {
    if (String(req.query.refresh || '') === '1') await refreshLeagueLifecycleIfStale();
    const { scope = 'discover', status, type } = req.query;
    let query = {};
    if (scope === 'mine') {
      const ids = await LeagueEntry.find({ userId: req.user._id }).distinct('leagueId');
      query._id = { $in: ids };
    } else if (scope === 'discover') {
      query.inviteOnly = { $ne: true };
      query.status = { $in: ['open', 'upcoming', 'live'] };
    }
    if (status) query.status = status;
    if (type) query.competitionType = type;
    const leagues = await League.find(query).sort({ officialSupremeLeague: -1, createdAt: -1 }).limit(100);
    const views = await Promise.all(leagues.map((league) => leagueView(league, req.user._id)));
    return success(res, { leagues: scope === 'discover' ? views.filter((league) => !league.isPast) : views });
  } catch (error) { next(error); }
});

app.get('/api/leagues/invite/:inviteCode', requireAuth, async (req, res, next) => {
  try {
    await refreshLeagueLifecycleIfStale();
    const inviteCode = normalizeInviteCode(req.params.inviteCode);
    if (!isValidInviteCode(inviteCode)) return failure(res, 400, 'Enter a valid league code.');
    const league = await League.findOne({ inviteCode });
    if (!league || league.status === 'cancelled') return failure(res, 404, 'No available league was found for that code.');
    const joinAccess = await localGrowth.assertLeagueJoinAllowed({ league, userId: req.user._id, inviteCode });
    const view = await leagueView(league, req.user._id);
    return success(res, {
      league: {
        ...view,
        inviteCode,
        canJoinWithCode: !view.joined && !view.isPast && ['open', 'upcoming', 'live'].includes(league.status),
        lateJoinWarning: joinAccess.lateJoinWarning,
        warningMessage: joinAccess.warningMessage,
      },
    });
  } catch (error) { next(error); }
});

app.post('/api/leagues', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    const {
      name, description, competitionType = 'weekly', startGameweek, endGameweek, entryAmount,
      maximumParticipants = 20, tieBreak = 'overall-rank', rulesAcknowledged,
      opponentEmail = '', inviteCode: requestedInviteCode = '',
      visibility = 'private', joinDeadlineAt, allowLateJoin = true,
    } = req.body;
    if (!name || !rulesAcknowledged) return failure(res, 400, 'League name and rules acknowledgement are required.');
    if (!req.user.fplManagerId) return failure(res, 400, 'Link your fantasy manager ID before creating and funding a league.');

    const inviteCode = normalizeInviteCode(requestedInviteCode);
    if (!isValidInviteCode(inviteCode)) {
      return failure(res, 400, 'Create a unique code using 6–16 letters, numbers or hyphens.');
    }
    if (await League.exists({ inviteCode })) return failure(res, 409, 'That league code is already in use. Choose another code.');

    const joiningDeadline = joinDeadlineAt ? new Date(joinDeadlineAt) : null;
    if (!joiningDeadline || Number.isNaN(joiningDeadline.getTime())) {
      return failure(res, 400, 'Choose a valid league joining deadline.');
    }
    if (joiningDeadline <= new Date()) {
      return failure(res, 400, 'The league joining deadline must be in the future.');
    }

    const entryFeeCents = Math.round(Number(entryAmount) * 100);
    if (!Number.isFinite(entryFeeCents) || entryFeeCents < 200) return failure(res, 400, 'Custom league entry must be at least $2.00.');
    const start = Number(startGameweek);
    const end = Number(endGameweek);
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end < start) return failure(res, 400, 'Enter a valid gameweek range.');

    let fplStartSchedule = null;
    let fplEndSchedule = null;
    if (FPL_DATA_MODE === 'public') {
      const bootstrap = await publicFantasyProvider.getBootstrap();
      [fplStartSchedule, fplEndSchedule] = await Promise.all([
        getFplGameweekSchedule(start, { bootstrap, includeFixtures: false }),
        getFplGameweekSchedule(end, { bootstrap, includeFixtures: true }),
      ]);
      if (!fplStartSchedule.deadlineAt) return failure(res, 409, `FPL has not published a joining deadline for Gameweek ${start}.`);
      if (fplStartSchedule.deadlineAt <= new Date()) {
        return failure(res, 409, `Gameweek ${start} has already reached its official FPL deadline. Choose a future gameweek.`);
      }
      if (joiningDeadline > fplStartSchedule.deadlineAt) {
        return failure(res, 409, `The joining deadline cannot be later than the official FPL Gameweek ${start} deadline (${fplStartSchedule.deadlineAt.toISOString()}).`);
      }
    }

    const isBandForBand = competitionType === 'band-for-band';
    const max = isBandForBand ? 2 : clamp(Number(maximumParticipants) || 20, 2, 1000);

    let invitedUser = null;
    if (isBandForBand) {
      const normalizedOpponent = normalizeEmail(opponentEmail);
      if (!normalizedOpponent || normalizedOpponent === req.user.email) return failure(res, 400, 'Select another registered user for a Band for Band challenge.');
      invitedUser = await User.findOne({ email: normalizedOpponent });
      if (!invitedUser) return failure(res, 404, 'The invited friend must already have a Supreme Fantasy League account.');
    }

    const league = await League.create({
      name, description, competitionType, cadence: competitionType, customLeague: true, officialSupremeLeague: false,
      startGameweek: start, endGameweek: end, currentGameweek: start, entryFeeCents,
      platformFeeBasisPoints: 1000, maximumParticipants: max, minimumParticipants: 2,
      inviteOnly: visibility !== 'public',
      inviteCode,
      invitedUserId: invitedUser?._id || null,
      invitedEmail: invitedUser?.email || '',
      tieBreak,
      status: 'draft',
      projectedPrizeCents: Math.round(max * entryFeeCents * 0.9), displayedPrizeCents: Math.round(max * entryFeeCents * 0.9),
      prizeType: 'projected', guaranteedPrize: false,
      rules: [
        'Entry is confirmed only after Paynow reports a successful payment.',
        'Members must use the exact league code supplied by the creator.',
        'Highest qualifying score wins unless the published competition format states otherwise.',
        `Tie-break: ${tieBreak}.`,
        ...(isBandForBand ? ['Both users enter the same amount. The challenge activates only after both users have paid.'] : []),
        'Final results are authoritative only after server-side result review.',
      ],
      createdBy: req.user._id,
      expiresAt: null,
      fplJoinDeadlineAt: fplStartSchedule?.deadlineAt || null,
      fplLastFixtureKickoffAt: fplEndSchedule?.lastFixtureKickoffAt || null,
    });

    await LeagueEntry.create({
      leagueId: league._id,
      userId: req.user._id,
      fantasyManagerId: req.user.fplManagerId,
      paymentStatus: 'pending',
      currentScore: 0,
      currentRank: 0,
      previousRank: 0,
    });

    const accessPolicy = await localGrowth.setLeagueAccessPolicy({
      league,
      creatorUserId: req.user._id,
      visibility,
      inviteCode,
      joinDeadlineAt: joiningDeadline,
      allowLateJoin: Boolean(allowLateJoin),
    });

    await emailService.notifyLeagueCreated(req.user, league);

    return success(res, {
      league: await leagueView(league, req.user._id),
      accessPolicy,
      checkoutRequired: true,
      message: 'League draft created. Complete checkout to activate it and become the first member.',
    }, 201);
  } catch (error) {
    if (error?.code === 11000) return failure(res, 409, 'That league code is already in use. Choose another code.');
    next(error);
  }
});

app.get('/api/leagues/:leagueId', requireAuth, async (req, res, next) => {
  try {
    const refreshRequested = String(req.query.refresh || '') === '1';
    if (refreshRequested) await refreshLeagueLifecycleIfStale();
    if (!mongoose.isValidObjectId(req.params.leagueId)) return failure(res, 404, 'League not found.');
    let league = await League.findById(req.params.leagueId);
    if (!league) return failure(res, 404, 'League not found.');
    // The first request renders cached standings immediately. The frontend then
    // issues ?refresh=1 automatically, so live FPL work never blocks navigation.
    if (refreshRequested && league.officialSupremeLeague && FPL_DATA_MODE === 'public') {
      try { await localGrowth.settleLeagueById(league._id, { forceDataChecked: false, trigger: 'user-league-page' }); }
      catch (settlementError) { console.warn('Opportunistic Supreme settlement skipped:', settlementError.message); }
      league = await League.findById(league._id);
    }
    if (refreshRequested) {
      try {
        const refreshed = await syncLeagueScores(league._id, { force: false });
        league = refreshed.league;
      } catch (syncError) {
        console.warn('League page score refresh failed:', syncError.message);
      }
    }
    const entry = await LeagueEntry.findOne({ leagueId: league._id, userId: req.user._id });
    const isCreator = String(league.createdBy || '') === String(req.user._id);
    if (league.inviteOnly && !isCreator && !entry) return failure(res, 403, 'Use the league code page to access this private league.');
    const leaderboard = await getLeagueLeaderboard(league._id, req.user._id);
    return success(res, { league: await leagueView(league, req.user._id), leaderboard });
  } catch (error) { next(error); }
});

// Legacy route is deliberately non-financial. All wallet spending now requires the explicit checkout confirmation flow.
app.post('/api/leagues/:leagueId/join', requireAuth, writeLimiter, async (req, res) => {
  return failure(res, 409, 'Choose Wallet balance or Paynow in the league checkout. Wallet deductions require an explicit confirmation.');
});

async function getLeagueLeaderboard(leagueId, currentUserId) {
  const entries = await LeagueEntry.find({ leagueId, paymentStatus: 'paid' }).sort({ currentScore: -1, latestOverallRank: 1, joinedAt: 1 }).populate('userId', 'fullName').lean();
  const profiles = await UserProfile.find({ userId: { $in: entries.map((e) => e.userId?._id).filter(Boolean) } }).select('userId profilePicture').lean();
  const profileMap = new Map(profiles.map((p) => [String(p.userId), p.profilePicture]));
  return entries.map((entry, index) => ({
    rank: index + 1,
    userId: entry.userId?._id,
    name: entry.userId?.fullName || 'Supreme Player',
    profilePicture: profileMap.get(String(entry.userId?._id)) || '',
    score: entry.currentScore,
    eligibilityStatus: entry.eligibilityStatus,
    prizeCents: entry.prizeCents,
    isCurrentUser: String(entry.userId?._id) === String(currentUserId),
  }));
}

app.post('/api/leagues/:leagueId/sync-scores', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.leagueId)) return failure(res, 404, 'League not found.');
    const league = await League.findById(req.params.leagueId);
    if (!league) return failure(res, 404, 'League not found.');
    const isMember = await LeagueEntry.exists({ leagueId: league._id, userId: req.user._id, paymentStatus: 'paid' });
    const isCreator = String(league.createdBy || '') === String(req.user._id);
    if (!isMember && !isCreator && req.user.role !== 'admin') return failure(res, 403, 'Only league members can refresh these standings.');
    const sync = await syncLeagueScores(league._id, { force: true });
    return success(res, {
      league: await leagueView(sync.league, req.user._id),
      leaderboard: await getLeagueLeaderboard(league._id, req.user._id),
      sync: {
        synced: sync.synced,
        failed: sync.failed,
        scoreThroughGameweek: sync.scoreThroughGameweek,
        message: sync.league.scoreSyncMessage,
      },
    });
  } catch (error) { next(error); }
});

app.get('/api/leagues/:leagueId/leaderboard', requireAuth, async (req, res, next) => {
  try {
    if (String(req.query.refresh || '') === '1') {
      await refreshLeagueLifecycleIfStale();
      await syncLeagueScores(req.params.leagueId, { force: false });
    }
    return success(res, { leaderboard: await getLeagueLeaderboard(req.params.leagueId, req.user._id) });
  } catch (error) { next(error); }
});

async function syncUserLeagueScores(userId, { force = false, limit = 20 } = {}) {
  const entries = await LeagueEntry.find({ userId, paymentStatus: 'paid' }).sort({ updatedAt: -1 }).select('leagueId').lean();
  const leagueIds = [...new Set(entries.map((entry) => String(entry.leagueId)).filter(Boolean))].slice(0, limit);
  const results = [];
  for (const leagueId of leagueIds) {
    try { results.push(await syncLeagueScores(leagueId, { force })); }
    catch (error) { console.warn(`Automatic league score refresh failed for ${leagueId}:`, error.message); }
  }
  return results;
}

// -----------------------------------------------------------------------------
// Wallet, Paynow checkout, transaction and subscription endpoints
// -----------------------------------------------------------------------------
app.get('/api/wallet', requireAuth, async (req, res, next) => {
  try {
    const { wallet } = await ensureUserResources(req.user._id);
    return success(res, {
      wallet: walletClientView(wallet),
      demoFunds: MOCK_PAYMENTS,
      paymentMode: PAYMENTS_MODE,
      paynowTestMode: PAYNOW_TEST_MODE,
      expressPaymentMethods: Object.values(PAYNOW_EXPRESS_METHODS),
    });
  } catch (error) { next(error); }
});

app.get('/api/transactions', requireAuth, async (req, res, next) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = clamp(Number(req.query.limit) || 10, 1, 100);
    const query = { userId: req.user._id };
    if (req.query.type) query.type = req.query.type;
    if (req.query.status) query.status = req.query.status;
    if (req.query.search) query.$or = [
      { reference: new RegExp(req.query.search, 'i') },
      { description: new RegExp(req.query.search, 'i') },
    ];
    if (req.query.from || req.query.to) {
      query.createdAt = {};
      if (req.query.from) query.createdAt.$gte = new Date(req.query.from);
      if (req.query.to) query.createdAt.$lte = new Date(`${req.query.to}T23:59:59.999Z`);
    }
    const [transactions, total] = await Promise.all([
      Transaction.find(query).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      Transaction.countDocuments(query),
    ]);
    return success(res, { transactions, pagination: { page, limit, total, pages: Math.max(1, Math.ceil(total / limit)) } });
  } catch (error) { next(error); }
});


function walletClientView(wallet) {
  if (!wallet) return null;
  const raw = typeof wallet.toObject === 'function' ? wallet.toObject() : wallet;
  return {
    ...raw,
    netSpendingCents: Number(raw.lifetimeEntryFeesCents || 0)
      + Number(raw.lifetimeSubscriptionFeesCents || 0)
      - Number(raw.lifetimePrizesCents || 0)
      - Number(raw.lifetimeRefundsCents || 0),
  };
}

function requireWalletIdempotencyKey(req) {
  const key = String(req.headers['idempotency-key'] || '').trim();
  if (!key || key.length > 160) {
    const error = new Error('A valid Idempotency-Key header is required for wallet payments. Refresh the checkout and try again.');
    error.status = 400;
    throw error;
  }
  return key;
}

async function debitWalletForPurchase({ userId, transaction, amountCents, lifetimeField }) {
  const operationReference = `${transaction.reference}:wallet-debit`;
  const wallet = await Wallet.findOneAndUpdate(
    {
      userId,
      availableBalanceCents: { $gte: amountCents },
      appliedTransactionReferences: { $ne: operationReference },
    },
    {
      $inc: { availableBalanceCents: -amountCents, [lifetimeField]: amountCents },
      $addToSet: { appliedTransactionReferences: operationReference },
      $set: {
        lastBalanceUpdateAt: new Date(),
        lastBalanceUpdateReason: `wallet-purchase:${transaction.reference}`,
        lastBalanceUpdateFunction: 'debitWalletForPurchase',
      },
    },
    { new: true }
  );
  if (wallet) return { wallet, newlyApplied: true };
  if (await walletOperationApplied(userId, operationReference)) {
    return { wallet: await Wallet.findOne({ userId }), newlyApplied: false };
  }
  return { wallet: null, newlyApplied: false };
}

async function reverseWalletPurchase({ userId, transaction, amountCents, lifetimeField, reason }) {
  const debitReference = `${transaction.reference}:wallet-debit`;
  if (!(await walletOperationApplied(userId, debitReference))) return null;
  return updateWalletBalances(
    userId,
    { availableBalanceCents: amountCents, [lifetimeField]: -amountCents },
    reason,
    'reverseWalletPurchase',
    {},
    `${transaction.reference}:wallet-reversal`
  );
}

async function completedWalletPurchaseResponse(transaction, extra = {}) {
  const wallet = await Wallet.findOne({ userId: transaction.userId });
  return {
    payment: paymentPublicView(transaction),
    wallet: walletClientView(wallet),
    ...extra,
  };
}

app.post('/api/payments/wallet/subscription', requireAuth, writeLimiter, async (req, res, next) => {
  let transaction = null;
  let debited = false;
  try {
    if (req.body.confirmWallet !== true) return failure(res, 400, 'Confirm that you want to pay from your Supreme wallet balance.');
    const idempotencyKey = requireWalletIdempotencyKey(req);
    const requestedPlanCode = normalizeSubscriptionPlanCode(req.body.planCode);
    const plan = resolveSubscriptionPlan(requestedPlanCode);
    if (!plan) return failure(res, 400, 'Unknown subscription plan.');

    const existing = await Transaction.findOne({ userId: req.user._id, type: 'subscription', 'metadata.idempotencyKey': idempotencyKey });
    if (existing) {
      if (existing.provider !== 'wallet') return failure(res, 409, 'This checkout reference already belongs to a Paynow payment. Close the checkout and start a new wallet payment.');
      transaction = existing;
      if (existing.status === 'completed') {
        const subscription = await Subscription.findOne({ paymentTransactionId: existing._id }).lean();
        return success(res, await completedWalletPurchaseResponse(existing, { subscription }), 200);
      }
      if (['rejected', 'cancelled', 'reversed'].includes(existing.status)) {
        return failure(res, 409, 'This wallet checkout attempt has already ended. Start a fresh wallet payment and try again.', [{
          code: 'wallet_checkout_terminal',
          reference: existing.reference,
          status: existing.status,
        }]);
      }
    }

    if (!transaction) {
      const paynowBlocker = await resolvePaynowBlockerBeforeWalletPurchase({
        userId: req.user._id,
        type: 'subscription',
        planCode: plan.planCode,
      });
      if (paynowBlocker?.state === 'completed') {
        return failure(res, 409, 'A Paynow payment for this plan completed while its status was being checked. Refresh your subscription before paying again.', [{
          code: 'paynow_subscription_already_completed',
          reference: paynowBlocker.transaction.reference,
        }]);
      }
      if (paynowBlocker?.state === 'pending') {
        return failure(res, 409, `Paynow checkout ${paynowBlocker.transaction.reference} is still pending. Its status was refreshed just now. Complete that checkout or wait for Paynow to confirm failure/cancellation before paying from the wallet.`, [{
          code: 'paynow_subscription_still_pending',
          reference: paynowBlocker.transaction.reference,
          status: paynowBlocker.transaction.status,
        }]);
      }

      await ensureUserResources(req.user._id);
      const reference = createReference('SUBW');
      try {
        transaction = await Transaction.create({
          userId: req.user._id,
          reference,
          type: 'subscription',
          direction: 'debit',
          amountCents: plan.amountCents,
          currency: 'USD',
          provider: 'wallet',
          providerReference: reference,
          status: 'processing',
          description: `${plan.planName} subscription`,
          metadata: {
            idempotencyKey,
            method: 'Supreme wallet',
            purpose: 'subscription',
            planCode: plan.planCode,
            walletConfirmedAt: new Date(),
          },
        });
      } catch (error) {
        if (error?.code !== 11000) throw error;
        transaction = await Transaction.findOne({ userId: req.user._id, type: 'subscription', 'metadata.idempotencyKey': idempotencyKey });
        if (!transaction) throw error;
        if (transaction.provider !== 'wallet') return failure(res, 409, 'This checkout reference already belongs to another payment source. Close the checkout and try again.');
      }
    }

    const debit = await debitWalletForPurchase({
      userId: req.user._id,
      transaction,
      amountCents: plan.amountCents,
      lifetimeField: 'lifetimeSubscriptionFeesCents',
    });
    if (!debit.wallet) {
      transaction = await Transaction.findByIdAndUpdate(transaction._id, {
        $set: { status: 'rejected', 'metadata.failureReason': 'Insufficient wallet balance', 'metadata.finalizedAt': new Date() },
      }, { new: true });
      await emailService.notifyPaymentUpdate(transaction);
      return failure(res, 400, 'Your wallet balance is not enough for this subscription. Deposit with Paynow or choose Paynow at checkout.');
    }
    debited = true;

    let subscription = await Subscription.findOne({ paymentTransactionId: transaction._id });
    if (!subscription) {
      try {
        subscription = await Subscription.create({
          ...plan,
          userId: req.user._id,
          status: 'pending-payment',
          startDate: null,
          paymentReference: transaction.reference,
          paymentProvider: 'wallet',
          paymentMethod: 'Supreme wallet',
          paymentTransactionId: transaction._id,
          walletSeedCents: SUBSCRIPTION_WALLET_SEED_CENTS,
        });
      } catch (createError) {
        if (createError?.code !== 11000) throw createError;
        subscription = await Subscription.findOne({ paymentTransactionId: transaction._id });
        if (!subscription) throw createError;
      }
    }

    const dates = await subscriptionDates(plan);
    await Subscription.updateMany(
      { userId: req.user._id, status: 'active', _id: { $ne: subscription._id } },
      { $set: { status: 'replaced', endDate: new Date(), validUntil: new Date(), lastValidityCheckAt: new Date() } }
    );
    subscription = await Subscription.findByIdAndUpdate(subscription._id, {
      $set: { status: 'active', ...dates, lastValidityCheckAt: new Date() },
    }, { new: true });

    transaction = await Transaction.findByIdAndUpdate(transaction._id, {
      $set: {
        status: 'completed',
        subscriptionId: subscription._id,
        'metadata.subscriptionId': subscription._id,
        'metadata.finalizedAt': new Date(),
        'metadata.walletBalanceAfterCents': debit.wallet.availableBalanceCents,
      },
    }, { new: true });
    await emailService.notifyPaymentUpdate(transaction);
    return success(res, await completedWalletPurchaseResponse(transaction, {
      subscription: subscription.toObject(),
      message: 'Wallet payment confirmed. Your subscription is active and your balance has been updated.',
    }), 201);
  } catch (error) {
    if (transaction && debited) {
      try {
        const completedSubscription = await Subscription.findOne({ paymentTransactionId: transaction._id, status: 'active' });
        if (completedSubscription) {
          const completedTransaction = await Transaction.findOneAndUpdate(
            { _id: transaction._id, status: 'processing' },
            { $set: { status: 'completed', subscriptionId: completedSubscription._id, 'metadata.subscriptionId': completedSubscription._id, 'metadata.finalizedAt': new Date(), 'metadata.recoveredInlineAt': new Date() } },
            { new: true }
          );
          if (completedTransaction) {
            await emailService.notifyPaymentUpdate(completedTransaction);
            return success(res, await completedWalletPurchaseResponse(completedTransaction, { subscription: completedSubscription.toObject() }), 200);
          }
        }
        const reversalClaim = await Transaction.findOneAndUpdate(
          { _id: transaction._id, status: 'processing' },
          { $set: { status: 'reversed', 'metadata.failureReason': String(error.message || error), 'metadata.finalizedAt': new Date() } },
          { new: true }
        );
        if (reversalClaim) {
          await reverseWalletPurchase({
            userId: req.user._id,
            transaction: reversalClaim,
            amountCents: reversalClaim.amountCents,
            lifetimeField: 'lifetimeSubscriptionFeesCents',
            reason: `wallet-subscription-rollback:${reversalClaim.reference}`,
          });
          await emailService.notifyPaymentUpdate(reversalClaim);
        } else {
          const latest = await Transaction.findById(transaction._id);
          if (latest?.status === 'completed') {
            const subscription = await Subscription.findOne({ paymentTransactionId: latest._id }).lean();
            return success(res, await completedWalletPurchaseResponse(latest, { subscription }), 200);
          }
        }
      } catch (rollbackError) {
        console.error('Wallet subscription rollback failed', transaction.reference, rollbackError.message);
      }
    }
    next(error);
  }
});

app.post('/api/payments/wallet/league-entry', requireAuth, writeLimiter, async (req, res, next) => {
  let transaction = null;
  let debited = false;
  let entry = null;
  try {
    if (req.body.confirmWallet !== true) return failure(res, 400, 'Confirm that you want to pay from your Supreme wallet balance.');
    const idempotencyKey = requireWalletIdempotencyKey(req);
    if (!mongoose.isValidObjectId(req.body.leagueId)) return failure(res, 404, 'League not found.');
    if (!req.user.fplManagerId) return failure(res, 400, 'Link your fantasy manager ID before joining a league.');

    const league = await League.findById(req.body.leagueId);
    if (!league || league.status === 'cancelled') return failure(res, 404, 'League not found.');
    if (leagueIsPast(league)) return failure(res, 400, 'This league has closed and can no longer accept entry payments.');
    const isCreator = String(league.createdBy || '') === String(req.user._id);
    let joinAccess = { warningMessage: '', lateJoinWarning: false };
    if (!isCreator) {
      if (!['open', 'upcoming', 'live'].includes(league.status)) return failure(res, 400, 'This league is not open for new members.');
      joinAccess = await localGrowth.assertLeagueJoinAllowed({ league, userId: req.user._id, inviteCode: req.body.inviteCode });
      if (league.competitionType === 'band-for-band' && String(league.invitedUserId || '') !== String(req.user._id)) {
        return failure(res, 403, 'This Band for Band challenge is assigned to another account.');
      }
    } else if (!['draft', 'open', 'upcoming'].includes(league.status)) {
      return failure(res, 400, 'This league entry can no longer be paid.');
    }

    const existing = await Transaction.findOne({ userId: req.user._id, type: 'entry-fee', 'metadata.idempotencyKey': idempotencyKey });
    if (existing) {
      if (existing.provider !== 'wallet') return failure(res, 409, 'This checkout reference already belongs to a Paynow payment. Close the checkout and start a new wallet payment.');
      transaction = existing;
      if (existing.status === 'completed') {
        return success(res, await completedWalletPurchaseResponse(existing, { league: await leagueView(league, req.user._id) }), 200);
      }
      if (['rejected', 'cancelled', 'reversed'].includes(existing.status)) {
        return failure(res, 409, 'This wallet checkout attempt has already ended. Start a fresh wallet payment and try again.', [{
          code: 'wallet_checkout_terminal',
          reference: existing.reference,
          status: existing.status,
        }]);
      }
    }

    entry = await LeagueEntry.findOne({ leagueId: league._id, userId: req.user._id });
    if (entry?.paymentStatus === 'paid') return failure(res, 409, 'You have already paid and joined this league.');
    if (entry?.paymentTransactionId) {
      const paynowBlocker = await resolvePaynowBlockerBeforeWalletPurchase({
        userId: req.user._id,
        type: 'entry-fee',
        leagueId: league._id,
      });
      if (paynowBlocker?.state === 'completed') {
        return failure(res, 409, 'Your Paynow payment for this league completed while its status was being checked. Refresh the league before paying again.', [{
          code: 'paynow_league_entry_already_completed',
          reference: paynowBlocker.transaction.reference,
        }]);
      }
      if (paynowBlocker?.state === 'pending') {
        return failure(res, 409, `Paynow checkout ${paynowBlocker.transaction.reference} is still pending. Its status was refreshed just now. Complete that checkout or wait for Paynow to confirm failure/cancellation before paying from the wallet.`, [{
          code: 'paynow_league_entry_still_pending',
          reference: paynowBlocker.transaction.reference,
          status: paynowBlocker.transaction.status,
        }]);
      }
    }

    if (!entry) {
      const reservedCount = await LeagueEntry.countDocuments({ leagueId: league._id, paymentStatus: { $in: ['paid', 'pending'] } });
      if (reservedCount >= league.maximumParticipants) return failure(res, 400, 'This league is full.');
      entry = await LeagueEntry.create({
        leagueId: league._id,
        userId: req.user._id,
        fantasyManagerId: req.user.fplManagerId,
        paymentStatus: 'pending',
        currentScore: 0,
        currentRank: 0,
        previousRank: 0,
      });
    }

    await ensureUserResources(req.user._id);
    if (!transaction) {
      const reference = createReference('ENTW');
      try {
        transaction = await Transaction.create({
          userId: req.user._id,
          leagueId: league._id,
          reference,
          type: 'entry-fee',
          direction: 'debit',
          amountCents: league.entryFeeCents,
          currency: 'USD',
          provider: 'wallet',
          providerReference: reference,
          status: 'processing',
          description: `League entry — ${league.name}`,
          metadata: {
            idempotencyKey,
            method: 'Supreme wallet',
            purpose: 'league-entry',
            leagueId: league._id,
            leagueEntryId: entry._id,
            walletConfirmedAt: new Date(),
            warningMessage: joinAccess.warningMessage || '',
          },
        });
      } catch (error) {
        if (error?.code !== 11000) throw error;
        transaction = await Transaction.findOne({ userId: req.user._id, type: 'entry-fee', 'metadata.idempotencyKey': idempotencyKey });
        if (!transaction) throw error;
        if (transaction.provider !== 'wallet') return failure(res, 409, 'This checkout reference already belongs to another payment source. Close the checkout and try again.');
      }
    }

    const debit = await debitWalletForPurchase({
      userId: req.user._id,
      transaction,
      amountCents: league.entryFeeCents,
      lifetimeField: 'lifetimeEntryFeesCents',
    });
    if (!debit.wallet) {
      transaction = await Transaction.findByIdAndUpdate(transaction._id, {
        $set: { status: 'rejected', 'metadata.failureReason': 'Insufficient wallet balance', 'metadata.finalizedAt': new Date() },
      }, { new: true });
      await LeagueEntry.updateOne({ _id: entry._id, paymentStatus: { $ne: 'paid' } }, { $set: { paymentStatus: 'failed' } });
      await emailService.notifyPaymentUpdate(transaction);
      return failure(res, 400, 'Your wallet balance is not enough for this league entry. Deposit with Paynow or choose Paynow at checkout.');
    }
    debited = true;

    const paidCountBefore = await LeagueEntry.countDocuments({ leagueId: league._id, paymentStatus: 'paid', _id: { $ne: entry._id } });
    entry = await LeagueEntry.findByIdAndUpdate(entry._id, {
      $set: {
        fantasyManagerId: req.user.fplManagerId,
        paymentStatus: 'paid',
        joinedAt: new Date(),
        paymentTransactionId: transaction._id,
        paymentReference: transaction.reference,
        paymentMethod: 'Supreme wallet',
        eligibilityStatus: joinAccess.lateJoinWarning ? 'warning' : 'eligible',
        eligibilityReason: joinAccess.warningMessage || 'Paid from Supreme wallet',
        currentRank: paidCountBefore + 1,
        previousRank: paidCountBefore + 1,
      },
    }, { new: true });

    const paidCount = paidCountBefore + 1;
    if (league.competitionType === 'band-for-band') league.status = paidCount >= 2 ? 'live' : 'upcoming';
    else if (paidCount >= league.maximumParticipants) league.status = 'full';
    else if (league.status === 'draft') league.status = 'open';
    await league.save();

    transaction = await Transaction.findByIdAndUpdate(transaction._id, {
      $set: {
        status: 'completed',
        'metadata.finalizedAt': new Date(),
        'metadata.walletBalanceAfterCents': debit.wallet.availableBalanceCents,
      },
    }, { new: true });
    await emailService.notifyPaymentUpdate(transaction);
    await emailService.notifyLeagueMembership(req.user._id, league._id, 'Supreme wallet payment');
    return success(res, await completedWalletPurchaseResponse(transaction, {
      league: await leagueView(league, req.user._id),
      warningMessage: joinAccess.warningMessage,
      message: 'Wallet payment confirmed. Your league entry is active and your balance has been updated.',
    }), 201);
  } catch (error) {
    if (transaction && debited) {
      try {
        const completedEntry = await LeagueEntry.findOne({
          paymentTransactionId: transaction._id,
          paymentStatus: 'paid',
        });
        if (completedEntry) {
          const completedTransaction = await Transaction.findOneAndUpdate(
            { _id: transaction._id, status: 'processing' },
            { $set: { status: 'completed', 'metadata.finalizedAt': new Date(), 'metadata.recoveredInlineAt': new Date() } },
            { new: true }
          );
          if (completedTransaction) {
            const completedLeague = await League.findById(completedTransaction.leagueId);
            await emailService.notifyPaymentUpdate(completedTransaction);
            return success(res, await completedWalletPurchaseResponse(completedTransaction, { league: completedLeague ? await leagueView(completedLeague, req.user._id) : null }), 200);
          }
        }
        const reversalClaim = await Transaction.findOneAndUpdate(
          { _id: transaction._id, status: 'processing' },
          { $set: { status: 'reversed', 'metadata.failureReason': String(error.message || error), 'metadata.finalizedAt': new Date() } },
          { new: true }
        );
        if (reversalClaim) {
          await reverseWalletPurchase({
            userId: req.user._id,
            transaction: reversalClaim,
            amountCents: reversalClaim.amountCents,
            lifetimeField: 'lifetimeEntryFeesCents',
            reason: `wallet-league-entry-rollback:${reversalClaim.reference}`,
          });
          if (entry) await LeagueEntry.updateOne({ _id: entry._id, paymentStatus: { $ne: 'paid' } }, { $set: { paymentStatus: 'failed' } });
          await emailService.notifyPaymentUpdate(reversalClaim);
        } else {
          const latest = await Transaction.findById(transaction._id);
          if (latest?.status === 'completed') {
            const league = await League.findById(latest.leagueId);
            return success(res, await completedWalletPurchaseResponse(latest, { league: league ? await leagueView(league, req.user._id) : null }), 200);
          }
        }
      } catch (rollbackError) {
        console.error('Wallet league-entry rollback failed', transaction.reference, rollbackError.message);
      }
    }
    if (error?.code === 11000) return failure(res, 409, 'This wallet payment was already submitted. Refresh the league and check your balance.');
    next(error);
  }
});


async function reconcileProcessingWalletPurchases() {
  const staleBefore = new Date(Date.now() - 2 * 60 * 1000);
  const transactions = await Transaction.find({
    provider: 'wallet',
    type: { $in: ['subscription', 'entry-fee'] },
    status: 'processing',
    updatedAt: { $lte: staleBefore },
  }).sort({ createdAt: 1 }).limit(50);
  const result = { checked: transactions.length, completed: 0, rejected: 0, reversed: 0, failed: 0 };

  for (let transaction of transactions) {
    try {
      const debitApplied = await walletOperationApplied(transaction.userId, `${transaction.reference}:wallet-debit`);
      if (!debitApplied) {
        transaction = await Transaction.findOneAndUpdate(
          { _id: transaction._id, status: 'processing' },
          { $set: { status: 'rejected', 'metadata.failureReason': 'Wallet debit was not applied before recovery timeout', 'metadata.finalizedAt': new Date() } },
          { new: true }
        );
        if (transaction) {
          result.rejected += 1;
          await emailService.notifyPaymentUpdate(transaction);
        }
        continue;
      }

      if (transaction.type === 'subscription') {
        const plan = resolveSubscriptionPlan(transaction.metadata?.planCode);
        if (!plan) throw new Error('The subscription plan no longer exists.');
        let subscription = await Subscription.findOne({ paymentTransactionId: transaction._id });
        if (!subscription) {
          try {
            subscription = await Subscription.create({
              ...plan,
              userId: transaction.userId,
              status: 'pending-payment',
              startDate: null,
              paymentReference: transaction.reference,
              paymentProvider: 'wallet',
              paymentMethod: 'Supreme wallet',
              paymentTransactionId: transaction._id,
              walletSeedCents: SUBSCRIPTION_WALLET_SEED_CENTS,
            });
          } catch (createError) {
            if (createError?.code !== 11000) throw createError;
            subscription = await Subscription.findOne({ paymentTransactionId: transaction._id });
            if (!subscription) throw createError;
          }
        }
        const dates = await subscriptionDates(plan);
        await Subscription.updateMany(
          { userId: transaction.userId, status: 'active', _id: { $ne: subscription._id } },
          { $set: { status: 'replaced', endDate: new Date(), validUntil: new Date(), lastValidityCheckAt: new Date() } }
        );
        await Subscription.updateOne(
          { _id: subscription._id },
          { $set: { status: 'active', ...dates, lastValidityCheckAt: new Date() } }
        );
        const wallet = await Wallet.findOne({ userId: transaction.userId });
        transaction = await Transaction.findOneAndUpdate(
          { _id: transaction._id, status: 'processing' },
          { $set: { status: 'completed', subscriptionId: subscription._id, 'metadata.subscriptionId': subscription._id, 'metadata.finalizedAt': new Date(), 'metadata.recoveredAt': new Date(), 'metadata.walletBalanceAfterCents': wallet?.availableBalanceCents ?? null } },
          { new: true }
        );
      } else {
        const league = await League.findById(transaction.leagueId || transaction.metadata?.leagueId);
        const entry = await LeagueEntry.findById(transaction.metadata?.leagueEntryId);
        if (!league || !entry || String(entry.userId) !== String(transaction.userId) || league.status === 'cancelled') {
          throw new Error('The league entry can no longer be completed.');
        }
        const paidCountBefore = await LeagueEntry.countDocuments({ leagueId: league._id, paymentStatus: 'paid', _id: { $ne: entry._id } });
        await LeagueEntry.updateOne(
          { _id: entry._id },
          { $set: { paymentStatus: 'paid', joinedAt: entry.joinedAt || new Date(), paymentTransactionId: transaction._id, paymentReference: transaction.reference, paymentMethod: 'Supreme wallet', currentRank: entry.currentRank || paidCountBefore + 1, previousRank: entry.previousRank || paidCountBefore + 1 } }
        );
        const paidCount = paidCountBefore + 1;
        if (league.competitionType === 'band-for-band') league.status = paidCount >= 2 ? 'live' : 'upcoming';
        else if (paidCount >= league.maximumParticipants) league.status = 'full';
        else if (league.status === 'draft') league.status = 'open';
        await league.save();
        const wallet = await Wallet.findOne({ userId: transaction.userId });
        transaction = await Transaction.findOneAndUpdate(
          { _id: transaction._id, status: 'processing' },
          { $set: { status: 'completed', 'metadata.finalizedAt': new Date(), 'metadata.recoveredAt': new Date(), 'metadata.walletBalanceAfterCents': wallet?.availableBalanceCents ?? null } },
          { new: true }
        );
        if (transaction) await emailService.notifyLeagueMembership(transaction.userId, league._id, 'Supreme wallet payment recovery');
      }

      if (transaction) {
        result.completed += 1;
        await emailService.notifyPaymentUpdate(transaction);
      }
    } catch (error) {
      result.failed += 1;
      console.error('Wallet purchase recovery failed', transaction.reference, error.message);
      try {
        const effectCompleted = transaction.type === 'subscription'
          ? await Subscription.exists({ paymentTransactionId: transaction._id, status: 'active' })
          : await LeagueEntry.exists({ paymentTransactionId: transaction._id, paymentStatus: 'paid' });
        if (effectCompleted) {
          const recovered = await Transaction.findOneAndUpdate(
            { _id: transaction._id, status: 'processing' },
            { $set: { status: 'completed', 'metadata.finalizedAt': new Date(), 'metadata.recoveredAt': new Date() } },
            { new: true }
          );
          if (recovered) {
            result.completed += 1;
            await emailService.notifyPaymentUpdate(recovered);
          }
          continue;
        }
        const reversalClaim = await Transaction.findOneAndUpdate(
          { _id: transaction._id, status: 'processing' },
          { $set: { status: 'reversed', 'metadata.failureReason': String(error.message || error), 'metadata.recoveredAt': new Date(), 'metadata.finalizedAt': new Date() } },
          { new: true }
        );
        if (reversalClaim) {
          const lifetimeField = reversalClaim.type === 'subscription' ? 'lifetimeSubscriptionFeesCents' : 'lifetimeEntryFeesCents';
          await reverseWalletPurchase({
            userId: reversalClaim.userId,
            transaction: reversalClaim,
            amountCents: reversalClaim.amountCents,
            lifetimeField,
            reason: `wallet-purchase-recovery-reversal:${reversalClaim.reference}`,
          });
          if (reversalClaim.type === 'entry-fee' && reversalClaim.metadata?.leagueEntryId) {
            await LeagueEntry.updateOne({ _id: reversalClaim.metadata.leagueEntryId, paymentStatus: { $ne: 'paid' } }, { $set: { paymentStatus: 'failed' } });
          }
          result.reversed += 1;
          await emailService.notifyPaymentUpdate(reversalClaim);
        }
      } catch (reversalError) {
        console.error('Wallet purchase recovery reversal failed', transaction.reference, reversalError.message);
      }
    }
  }
  return result;
}

async function createPaynowPaymentRecord({ req, type, amountCents, method, phone, plan = null, league = null, leagueEntry = null }) {
  const idempotencyKey = String(req.headers['idempotency-key'] || '').trim();
  if (idempotencyKey) {
    const existing = await Transaction.findOne({ userId: req.user._id, type, 'metadata.idempotencyKey': idempotencyKey });
    if (existing) return existing;
  }

  await ensureUserResources(req.user._id);
  const referencePrefix = type === 'subscription' ? 'SUB' : type === 'entry-fee' ? 'ENT' : 'DEP';
  const reference = createReference(referencePrefix);
  let subscription = null;
  if (type === 'subscription') {
    subscription = await Subscription.create({
      ...plan,
      userId: req.user._id,
      status: 'pending-payment',
      startDate: null,
      paymentReference: reference,
      paymentProvider: MOCK_PAYMENTS ? 'mock' : 'paynow',
      paymentMethod: method,
      walletSeedCents: SUBSCRIPTION_WALLET_SEED_CENTS,
    });
  }

  const description = type === 'deposit'
    ? `Wallet deposit via ${PAYNOW_EXPRESS_METHODS[method]?.label || method}`
    : type === 'subscription'
      ? `${plan.planName} subscription`
      : `League entry — ${league.name}`;

  let transaction = await Transaction.create({
    userId: req.user._id,
    leagueId: league?._id || null,
    subscriptionId: subscription?._id || null,
    reference,
    type,
    direction: type === 'deposit' ? 'credit' : 'debit',
    amountCents,
    currency: 'USD',
    provider: MOCK_PAYMENTS ? 'mock' : 'paynow',
    status: 'pending',
    description,
    metadata: {
      method,
      phone: normalizeZimbabwePhone(phone),
      purpose: type === 'entry-fee' ? 'league-entry' : type,
      planCode: plan?.planCode || '',
      subscriptionId: subscription?._id || null,
      leagueId: league?._id || null,
      leagueEntryId: leagueEntry?._id || null,
      ...(idempotencyKey ? { idempotencyKey } : {}),
    },
  });
  if (subscription) await Subscription.findByIdAndUpdate(subscription._id, { $set: { paymentTransactionId: transaction._id } });
  if (leagueEntry) {
    await LeagueEntry.findByIdAndUpdate(leagueEntry._id, {
      $set: {
        paymentStatus: 'pending',
        paymentTransactionId: transaction._id,
        paymentReference: reference,
        paymentMethod: method,
      },
    });
  }

  if (MOCK_PAYMENTS) {
    if (type === 'deposit') {
      await updateWalletBalances(req.user._id, { pendingBalanceCents: amountCents }, `Mock deposit ${reference} pending`, 'createPaynowPaymentRecord', {}, `${reference}:pending`);
      transaction = await Transaction.findByIdAndUpdate(transaction._id, { $set: { 'metadata.pendingBalanceApplied': true } }, { new: true });
    }
    return finalizeSuccessfulPayment(transaction, { status: 'Paid', reference, amount: (amountCents / 100).toFixed(2), paynowreference: `MOCK-${reference}` });
  }

  if (!PAYNOW_PAYMENTS) {
    const error = new Error('Paynow checkout is not enabled. Set PAYMENTS_MODE=paynow.');
    error.status = 503;
    throw error;
  }

  try {
    const response = await initiatePaynowExpress({ reference, amountCents, description: transaction.description, user: req.user, method, phone });
    const metadata = {
      ...transaction.metadata,
      pollUrl: response.pollurl || '',
      paynowStatus: response.status || 'Created',
      instructions: response.instructions || '',
      authorizationCode: response.authorizationcode || '',
      authorizationExpires: response.authorizationexpires || '',
      deepLink: response.deepLink || '',
      otpReference: response.otpreference || '',
      remoteOtpUrl: response.remoteotpurl || '',
      normalizedPhone: response.normalizedPhone,
    };
    transaction = await Transaction.findByIdAndUpdate(
      transaction._id,
      {
        $set: {
          status: 'processing',
          providerReference: response.paynowreference || '',
          metadata,
        },
      },
      { new: true }
    );
    if (type === 'deposit') {
      await updateWalletBalances(req.user._id, { pendingBalanceCents: amountCents }, `Paynow deposit ${reference} initiated`, 'createPaynowPaymentRecord', {}, `${reference}:pending`);
      transaction = await Transaction.findByIdAndUpdate(transaction._id, { $set: { 'metadata.pendingBalanceApplied': true } }, { new: true });
    }
    await emailService.notifyPaymentUpdate(transaction);
    return transaction;
  } catch (error) {
    const failedTransaction = await Transaction.findByIdAndUpdate(
      transaction._id,
      { $set: { status: 'rejected', 'metadata.initiationError': error.message, 'metadata.paynowStatus': 'Initiation failed' } },
      { new: true }
    );
    if (subscription) await Subscription.findByIdAndUpdate(subscription._id, { $set: { status: 'payment-failed' } });
    if (leagueEntry) await LeagueEntry.findByIdAndUpdate(leagueEntry._id, { $set: { paymentStatus: 'failed' } });
    await emailService.notifyPaymentUpdate(failedTransaction);
    throw error;
  }
}

app.post('/api/payments/paynow/deposit', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    const amountCents = Math.round(Number(req.body.amount) * 100);
    if (!Number.isFinite(amountCents) || amountCents <= 0) return failure(res, 400, 'Enter a valid deposit amount.');
    if (!PAYNOW_EXPRESS_METHODS[req.body.method]) return failure(res, 400, 'Select a supported Paynow Express Checkout method.');
    const transaction = await createPaynowPaymentRecord({ req, type: 'deposit', amountCents, method: req.body.method, phone: req.body.phone });
    return success(res, { payment: paymentPublicView(transaction), wallet: walletClientView(await Wallet.findOne({ userId: req.user._id })), demoWarning: MOCK_PAYMENTS ? 'Mock Paynow checkout completed. No real payment was processed.' : '' }, 201);
  } catch (error) { next(error); }
});

app.post('/api/payments/paynow/league-entry', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.body.leagueId)) return failure(res, 404, 'League not found.');
    if (!PAYNOW_EXPRESS_METHODS[req.body.method]) return failure(res, 400, 'Select a supported Paynow Express Checkout method.');
    if (!req.user.fplManagerId) return failure(res, 400, 'Link your fantasy manager ID before joining a league.');

    const league = await League.findById(req.body.leagueId);
    if (!league || league.status === 'cancelled') return failure(res, 404, 'League not found.');
    if (leagueIsPast(league)) return failure(res, 400, 'This league has closed and can no longer accept entry payments.');
    const isCreator = String(league.createdBy || '') === String(req.user._id);
    let joinAccess = { warningMessage: '', lateJoinWarning: false };
    if (!isCreator) {
      if (!['open', 'upcoming', 'live'].includes(league.status)) return failure(res, 400, 'This league is not open for new members.');
      joinAccess = await localGrowth.assertLeagueJoinAllowed({
        league,
        userId: req.user._id,
        inviteCode: req.body.inviteCode,
      });
      if (league.competitionType === 'band-for-band' && String(league.invitedUserId || '') !== String(req.user._id)) {
        return failure(res, 403, 'This Band for Band challenge is assigned to another account.');
      }
    } else if (!['draft', 'open', 'upcoming'].includes(league.status)) {
      return failure(res, 400, 'This league entry can no longer be paid.');
    }

    let entry = await LeagueEntry.findOne({ leagueId: league._id, userId: req.user._id });
    if (entry?.paymentStatus === 'paid') return failure(res, 409, 'You have already paid and joined this league.');

    if (!entry) {
      const reservedCount = await LeagueEntry.countDocuments({ leagueId: league._id, paymentStatus: { $in: ['paid', 'pending'] } });
      if (reservedCount >= league.maximumParticipants) return failure(res, 400, 'This league is full.');
      entry = await LeagueEntry.create({
        leagueId: league._id,
        userId: req.user._id,
        fantasyManagerId: req.user.fplManagerId,
        paymentStatus: 'pending',
        currentScore: 0,
        currentRank: 0,
        previousRank: 0,
      });
    } else {
      entry.fantasyManagerId = req.user.fplManagerId;
      entry.paymentStatus = 'pending';
      await entry.save();
    }

    if (entry.paymentTransactionId) {
      const existing = await Transaction.findById(entry.paymentTransactionId);
      if (existing && ['pending', 'processing'].includes(existing.status)) {
        return success(res, { payment: paymentPublicView(existing), league: await leagueView(league, req.user._id) }, 200);
      }
    }

    const transaction = await createPaynowPaymentRecord({
      req,
      type: 'entry-fee',
      amountCents: league.entryFeeCents,
      method: req.body.method,
      phone: req.body.phone,
      league,
      leagueEntry: entry,
    });
    return success(res, {
      payment: paymentPublicView(transaction),
      wallet: walletClientView(await Wallet.findOne({ userId: req.user._id })),
      league: await leagueView(league, req.user._id),
      demoWarning: MOCK_PAYMENTS ? 'Mock Paynow checkout completed. No real payment was processed.' : '',
      warningMessage: joinAccess.warningMessage,
    }, 201);
  } catch (error) {
    if (error?.code === 11000) return failure(res, 409, 'You already have an entry for this league.');
    next(error);
  }
});

app.post('/api/payments/paynow/subscription', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    const requestedPlanCode = normalizeSubscriptionPlanCode(req.body.planCode);
    const plan = resolveSubscriptionPlan(requestedPlanCode);
    if (!plan) {
      return failure(res, 400, 'Unknown subscription plan.', [{
        field: 'planCode',
        code: 'invalid_subscription_plan',
        received: requestedPlanCode,
        accepted: Object.values(PLANS).map((item) => item.planCode),
      }]);
    }
    if (!PAYNOW_EXPRESS_METHODS[req.body.method]) return failure(res, 400, 'Select a supported Paynow Express Checkout method.');
    const transaction = await createPaynowPaymentRecord({ req, type: 'subscription', amountCents: plan.amountCents, method: req.body.method, phone: req.body.phone, plan });
    return success(res, { payment: paymentPublicView(transaction), wallet: walletClientView(await Wallet.findOne({ userId: req.user._id })), demoWarning: MOCK_PAYMENTS ? 'Mock Paynow checkout completed. No real payment was processed.' : '' }, 201);
  } catch (error) { next(error); }
});

app.post('/api/payments/paynow/:reference/otp', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    const transaction = await Transaction.findOne({ reference: req.params.reference, userId: req.user._id, provider: { $in: ['paynow', 'mock'] } });
    if (!transaction) return failure(res, 404, 'Payment was not found.');
    if (transaction.metadata?.method !== 'omari' || !transaction.metadata?.remoteOtpUrl) return failure(res, 400, 'This payment does not require an O\'mari OTP.');
    const otp = String(req.body.otp || '').replace(/\s/g, '');
    if (!/^\d{4,8}$/.test(otp)) return failure(res, 400, 'Enter the OTP sent to the O\'mari mobile number.');
    const response = await postPaynow(transaction.metadata.remoteOtpUrl, { id: PAYNOW_INTEGRATION_ID, otp, status: 'Message' });
    await Transaction.updateOne({ _id: transaction._id }, { $set: { 'metadata.otpSubmittedAt': new Date() } });
    const updated = await processPaynowStatus(transaction, response);
    return success(res, { payment: paymentPublicView(updated), wallet: walletClientView(await Wallet.findOne({ userId: req.user._id })) });
  } catch (error) { next(error); }
});

app.get('/api/payments/paynow/:reference/status', requireAuth, async (req, res, next) => {
  try {
    let transaction = await Transaction.findOne({ reference: req.params.reference, userId: req.user._id });
    if (!transaction) return failure(res, 404, 'Payment was not found.');
    if (transaction.provider === 'paynow' && transaction.metadata?.pollUrl && !['completed', 'rejected', 'cancelled', 'reversed'].includes(transaction.status)) {
      const status = await pollPaynowTransaction(transaction);
      if (status) transaction = await processPaynowStatus(transaction, status);
    }
    return success(res, { payment: paymentPublicView(transaction), wallet: walletClientView(await Wallet.findOne({ userId: req.user._id })) });
  } catch (error) { next(error); }
});

app.post('/api/payments/paynow/result', async (req, res, next) => {
  try {
    const entries = Object.entries(req.body || {}).map(([key, value]) => [String(key).toLowerCase(), String(value)]);
    const parsed = { entries, data: Object.fromEntries(entries) };
    if (!paynowHashIsValid(parsed)) return res.status(400).send('INVALID HASH');
    const transaction = await Transaction.findOne({ reference: parsed.data.reference });
    if (!transaction) return res.status(200).send('OK');
    let confirmed = parsed.data;
    if (transaction.metadata?.pollUrl && (paynowStatusIsPaid(parsed.data.status) || paynowStatusIsRefunded(parsed.data.status))) {
      confirmed = await pollPaynowTransaction(transaction);
    }
    await processPaynowStatus(transaction, confirmed);
    return res.status(200).send('OK');
  } catch (error) { next(error); }
});

// Retired deposit endpoint. The Wallet page uses /api/payments/paynow/deposit.
app.post('/api/deposits/request', requireAuth, writeLimiter, async (req, res) => {
  if (!MOCK_PAYMENTS) return failure(res, 409, 'Use the Paynow checkout endpoint for live deposits.');
  return failure(res, 410, 'This deposit endpoint has been retired. Use Paynow checkout.');
});

app.post('/api/withdrawals/request', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    const amountCents = Math.round(Number(req.body.amount) * 100);
    const method = String(req.body.method || '').trim();
    if (!Number.isFinite(amountCents) || amountCents < WITHDRAWAL_MINIMUM_CENTS) return failure(res, 400, 'The minimum withdrawal is US$5.00.');
    if (!PAYMENT_METHODS.includes(method)) return failure(res, 400, 'Select a supported withdrawal method.');
    if (req.body.currency && String(req.body.currency).toUpperCase() !== 'USD') return failure(res, 400, 'Withdrawals are paid only to USD accounts.');

    const destination = { method, currency: 'USD' };
    if (method === 'Bank Transfer') {
      const bankName = String(req.body.bankName || '').trim();
      const branchNumber = String(req.body.branchNumber || '').replace(/\s+/g, '');
      const accountNumber = String(req.body.accountNumber || '').replace(/\s+/g, '');
      if (!ZIMBABWE_USD_BANKS.includes(bankName)) return failure(res, 400, 'Select a supported Zimbabwean bank.');
      if (!/^[A-Za-z0-9-]{2,20}$/.test(branchNumber)) return failure(res, 400, 'Enter a valid branch number.');
      if (!/^[A-Za-z0-9-]{5,34}$/.test(accountNumber)) return failure(res, 400, 'Enter a valid USD account number.');
      Object.assign(destination, { bankName, branchNumber, accountNumber, accountLast4: accountNumber.slice(-4) });
    } else {
      const accountNumber = String(req.body.accountNumber || req.body.maskedAccount || '').trim();
      if (!/^[+0-9][0-9 +()-]{6,24}$/.test(accountNumber)) return failure(res, 400, 'Enter the registered mobile-money number.');
      Object.assign(destination, { accountNumber, accountLast4: accountNumber.replace(/\D/g, '').slice(-4) });
    }

    const idempotencyKey = String(req.headers['idempotency-key'] || '').trim();
    if (idempotencyKey) {
      const existing = await Transaction.findOne({ userId: req.user._id, type: 'withdrawal', 'metadata.idempotencyKey': idempotencyKey });
      if (existing) return success(res, { transaction: existing });
    }

    const reference = createReference('WDR');
    const wallet = await Wallet.findOneAndUpdate(
      { userId: req.user._id, availableBalanceCents: { $gte: amountCents }, appliedTransactionReferences: { $ne: `${reference}:reserve` } },
      { $inc: { availableBalanceCents: -amountCents, pendingBalanceCents: amountCents }, $addToSet: { appliedTransactionReferences: `${reference}:reserve` }, $set: { lastBalanceUpdateAt: new Date(), lastBalanceUpdateReason: `withdrawal-reserved:${reference}`, lastBalanceUpdateFunction: 'withdrawalsRequestEndpoint' } },
      { new: true }
    );
    if (!wallet) return failure(res, 400, 'Withdrawal amount cannot exceed the available balance.');

    let transaction;
    try {
      transaction = await Transaction.create({ userId: req.user._id, reference, type: 'withdrawal', direction: 'debit', amountCents, currency: 'USD', provider: 'manual-payout-review', status: 'pending', description: `USD withdrawal request via ${method}`, metadata: { ...destination, idempotencyKey, requestedAt: new Date(), estimatedBusinessDays: '3-4', walletReservationReference: `${reference}:reserve` } });
    } catch (error) {
      await updateWalletBalances(req.user._id, { availableBalanceCents: amountCents, pendingBalanceCents: -amountCents }, `withdrawal-request-rollback:${reference}`, 'withdrawalsRequestEndpoint', {}, `${reference}:rollback`);
      throw error;
    }
    await emailService.notifyPaymentUpdate(transaction);
    return success(res, { transaction, message: 'Withdrawal submitted. Payouts are made only in USD and may take 3–4 business days.' }, 201);
  } catch (error) { next(error); }
});

app.get('/api/subscription', requireAuth, async (req, res, next) => {
  try {
    const [subscription, resources, history] = await Promise.all([
      currentSubscription(req.user._id),
      ensureUserResources(req.user._id),
      Subscription.find({ userId: req.user._id }).sort({ createdAt: -1 }).lean(),
    ]);
    return success(res, {
      subscription,
      wallet: walletClientView(resources.wallet),
      history,
      plans: Object.values(PLANS),
      mockCheckout: MOCK_PAYMENTS,
      paymentMode: PAYMENTS_MODE,
      paynowTestMode: PAYNOW_TEST_MODE,
      expressPaymentMethods: Object.values(PAYNOW_EXPRESS_METHODS),
      walletSeedCents: SUBSCRIPTION_WALLET_SEED_CENTS,
    });
  } catch (error) { next(error); }
});

// Retired subscription endpoint. The Subscription page uses unified Wallet / Paynow checkout.
app.post('/api/subscription/select', requireAuth, writeLimiter, async (req, res) => {
  if (!MOCK_PAYMENTS) return failure(res, 409, 'Use the Wallet / Paynow subscription checkout.');
  return failure(res, 410, 'This subscription endpoint has been retired. Use the unified payment checkout.');
});

// -----------------------------------------------------------------------------
// Leaderboards and dashboard
// -----------------------------------------------------------------------------
async function competitionLeaderboards(currentUserId, { refreshScores = false } = {}) {
  const categories = [
    ['Weekly Cup', 'weekly'],
    ['Bi-Weekly Cup', 'bi-weekly'],
    ['Monthly Cup', 'monthly'],
    ['Half-Season Cup', 'half-season'],
    ['Season Cup', 'season'],
  ];

  return Promise.all(categories.map(async ([name, key]) => {
    const league = await League.findOne({
      $or: [{ cadence: key }, { competitionType: key }],
      status: { $in: ['open', 'full', 'upcoming', 'live', 'awaiting-review', 'settled'] },
    }).sort({ officialSupremeLeague: -1, startGameweek: -1, createdAt: -1 });

    if (league && refreshScores) {
      try { await syncLeagueScores(league._id, { force: false }); }
      catch (error) { console.warn(`Leaderboard refresh failed for ${league._id}:`, error.message); }
    }

    return {
      key,
      name,
      leagueId: league?._id || null,
      leagueName: league?.name || '',
      status: league?.status || 'unavailable',
      scoreThroughGameweek: league?.scoreThroughGameweek || 0,
      lastScoredAt: league?.lastScoredAt || null,
      rows: league ? await getLeagueLeaderboard(league._id, currentUserId) : [],
    };
  }));
}

async function dashboardSupremeOffers(userId, limit = 8) {
  const now = new Date();
  const leagues = await League.find({
    officialSupremeLeague: true,
    status: { $in: ['open', 'upcoming'] },
    fplJoinDeadlineAt: { $gt: now },
  })
    .sort({ fplJoinDeadlineAt: 1, startGameweek: 1 })
    .limit(limit)
    .select('name description cadence competitionType startGameweek endGameweek entryFeeCents displayedPrizeCents fplJoinDeadlineAt status')
    .lean();
  if (!leagues.length) return [];
  const leagueIds = leagues.map((league) => league._id);
  const entries = userId
    ? await LeagueEntry.find({ leagueId: { $in: leagueIds }, userId }).select('leagueId paymentStatus').lean()
    : [];
  const joined = new Map(entries.map((entry) => [String(entry.leagueId), entry.paymentStatus]));
  return leagues.map((league) => ({
    id: league._id,
    name: league.name,
    description: league.description,
    cadence: league.cadence || league.competitionType,
    startGameweek: league.startGameweek,
    endGameweek: league.endGameweek,
    entryFeeCents: Number(league.entryFeeCents || 0),
    prizeCents: (league.cadence || league.competitionType) === 'clash-captains'
      ? nonNegativeIntegerFromEnv('SUPREME_CLASH_CAPTAINS_PRIZE_CENTS', 300)
      : Number(league.displayedPrizeCents || 0),
    joinDeadlineAt: league.fplJoinDeadlineAt,
    status: league.status,
    joined: joined.get(String(league._id)) === 'paid',
  }));
}

function cachedDashboardGameState(team, offers) {
  const next = (offers || []).find((offer) => offer.joinDeadlineAt && new Date(offer.joinDeadlineAt) > new Date()) || null;
  const gameweek = Number(team?.snapshot?.gameweek || next?.startGameweek || 0);
  return {
    currentGameweek: gameweek,
    syncGameweek: gameweek,
    nextDeadline: next?.joinDeadlineAt || null,
    source: 'cached-platform-data',
  };
}

app.get('/api/leaderboards', requireAuth, async (req, res, next) => {
  try {
    const refreshRequested = String(req.query.refresh || '') === '1';
    if (refreshRequested) await refreshLeagueLifecycleIfStale();
    const [competitions, earnings] = await Promise.all([
      competitionLeaderboards(req.user._id, { refreshScores: refreshRequested }),
      getEarningsLeaderboard(req.user._id, 10),
    ]);
    return success(res, { competitions, earnings, refreshing: refreshRequested });
  } catch (error) { next(error); }
});

app.get('/api/dashboard', requireAuth, async (req, res, next) => {
  try {
    const refreshRequested = String(req.query.refresh || '') === '1';
    if (refreshRequested && req.user.fplManagerId) {
      // This is the non-blocking follow-up request started by the already-rendered
      // dashboard. Keep the work bounded and cache-aware.
      await Promise.allSettled([
        refreshLeagueLifecycleIfStale(),
        persistFantasyTeamSnapshot(req.user, { force: false }),
        syncUserLeagueScores(req.user._id, { force: false, limit: 8 }),
      ]);
    }

    const [{ wallet }, team, subscription, entries, transactions, competitions, earningsLeaderboard, availableCompetitions] = await Promise.all([
      ensureUserResources(req.user._id),
      buildTeamPayload(req.user, { refresh: false }),
      currentSubscription(req.user._id),
      req.user.fplManagerId ? LeagueEntry.find({ userId: req.user._id }).populate('leagueId').sort({ updatedAt: -1 }).limit(30).lean() : Promise.resolve([]),
      Transaction.find({ userId: req.user._id }).sort({ createdAt: -1 }).limit(5).lean(),
      req.user.fplManagerId ? competitionLeaderboards(req.user._id, { refreshScores: false }) : Promise.resolve([]),
      getEarningsLeaderboard(req.user._id, 10),
      dashboardSupremeOffers(req.user._id),
    ]);

    const myLeagues = await Promise.all(entries.filter((e) => e.leagueId).map((entry) => leagueView(entry.leagueId, req.user._id)));
    const summary = {
      gameweekPoints: team.linked ? Number(team.snapshot?.gameweekPoints || 0) : 0,
      overallRank: team.linked ? (team.snapshot?.overallRank ?? null) : null,
      activeLeagues: myLeagues.filter((l) => ['live', 'open', 'upcoming'].includes(l.status)).length,
      walletBalanceCents: wallet.availableBalanceCents,
      pendingBalanceCents: wallet.pendingBalanceCents,
      subscription: subscription?.planName || 'No active plan',
    };
    return success(res, {
      gameState: cachedDashboardGameState(team, availableCompetitions),
      summary,
      myLeagues,
      team,
      availableCompetitions,
      onboarding: {
        needsTeamLink: !Boolean(req.user.fplManagerId),
        nextStep: req.user.fplManagerId ? 'join-league' : 'link-team',
      },
      transactions,
      pendingFinancialRequests: transactions.filter((t) => t.status === 'pending'),
      subscription,
      leaderboards: competitions,
      earningsLeaderboard,
      demoFunds: MOCK_PAYMENTS,
      providerAvailable: true,
      refreshing: refreshRequested,
    });
  } catch (error) { next(error); }
});


// -----------------------------------------------------------------------------
// User support tickets
// -----------------------------------------------------------------------------
app.get('/api/support/tickets', requireAuth, async (req, res, next) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.user._id })
      .sort({ lastActivityAt: -1, createdAt: -1 })
      .limit(100)
      .lean();
    return success(res, { tickets });
  } catch (error) { next(error); }
});

app.post('/api/support/tickets', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    const subject = String(req.body.subject || '').trim();
    const message = String(req.body.message || '').trim();
    const allowedCategories = new Set(['general', 'account', 'league', 'payment', 'subscription', 'technical']);
    const category = allowedCategories.has(req.body.category) ? req.body.category : 'general';
    if (subject.length < 3) return failure(res, 400, 'Enter a short subject for your support request.');
    if (message.length < 10) return failure(res, 400, 'Describe the issue in at least 10 characters.');

    const ticket = await SupportTicket.create({
      userId: req.user._id,
      ticketNumber: createReference('SUP'),
      subject,
      category,
      priority: 'normal',
      status: 'open',
      message,
      lastActivityAt: new Date(),
    });

    await localGrowth.notifySupportTicketReceived({ ticket, user: req.user });
    return success(res, {
      ticket,
      message: 'Your support request has been received and will be attended to shortly.',
    }, 201);
  } catch (error) { next(error); }
});

// -----------------------------------------------------------------------------
// Local email diagnostics
// -----------------------------------------------------------------------------
app.post('/api/notifications/test-email', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    return success(res, { notification: await emailService.sendTestEmail(req.user) });
  } catch (error) { next(error); }
});

app.post('/api/internal/local/team-reminders', requireAdmin, writeLimiter, async (req, res, next) => {
  try {
    return success(res, await emailService.sendStaleTeamReminders());
  } catch (error) { next(error); }
});

app.post('/api/internal/local/user-email-reminders', requireAdmin, writeLimiter, async (req, res, next) => {
  try {
    return success(res, await localGrowth.sendScheduledUserEmails());
  } catch (error) { next(error); }
});

// -----------------------------------------------------------------------------
// Administration API
// -----------------------------------------------------------------------------
const ADMIN_SIGNUP_KEY = String(process.env.ADMIN_SIGNUP_KEY || '').trim();
const adminPublicUser = (user) => ({ id: user._id, fullName: user.fullName, email: user.email, phone: user.phone, role: user.role, status: user.status, createdAt: user.createdAt });
const escapeRegex = (value = '') => String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const pageOptions = (req, fallback = 25) => ({
  page: Math.max(1, Number(req.query.page || 1)),
  limit: clamp(Number(req.query.limit || fallback), 1, 100),
});

function parseAdminAnalyticsRange(req) {
  const todayStart = new Date();
  todayStart.setUTCHours(0, 0, 0, 0);

  // Default to 30 calendar months including the current month.
  const defaultFrom = new Date(Date.UTC(
    todayStart.getUTCFullYear(),
    todayStart.getUTCMonth() - 29,
    1
  ));

  const rawFrom = req.query.from ? new Date(String(req.query.from)) : defaultFrom;
  const rawTo = req.query.to
    ? new Date(String(req.query.to))
    : new Date(todayStart.getTime() + 86400000);

  const from = Number.isNaN(rawFrom.getTime()) ? defaultFrom : rawFrom;
  let toExclusive = Number.isNaN(rawTo.getTime())
    ? new Date(todayStart.getTime() + 86400000)
    : rawTo;

  // Date-only `to` values are interpreted as inclusive by the admin UI.
  if (/^\d{4}-\d{2}-\d{2}$/.test(String(req.query.to || ''))) {
    toExclusive = new Date(toExclusive.getTime() + 86400000);
  }

  if (toExclusive <= from) {
    toExclusive = new Date(from.getTime() + 86400000);
  }

  // Prevent accidental very large analytics queries. The maximum is 30
  // calendar months, measured backwards from the selected end date.
  const maxFrom = new Date(Date.UTC(
    toExclusive.getUTCFullYear(),
    toExclusive.getUTCMonth() - 29,
    1
  ));
  if (from < maxFrom) return { from: maxFrom, toExclusive };

  return { from, toExclusive };
}

function adminCashInMatch() {
  return {
    status: 'completed',
    provider: { $in: ['paynow', 'mock'] },
    type: { $in: ['deposit', 'subscription', 'entry-fee'] },
    direction: 'credit',
  };
}

function adminRevenueMatch() {
  return {
    status: 'completed',
    type: { $in: ['subscription', 'entry-fee', 'platform-fee'] },
    direction: 'credit',
  };
}

function adminBucketStart(date, groupBy) {
  const value = new Date(date);
  if (groupBy === 'month') return new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth(), 1));
  if (groupBy === 'week') {
    const day = value.getUTCDay();
    const mondayOffset = (day + 6) % 7;
    return new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth(), value.getUTCDate() - mondayOffset));
  }
  return new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth(), value.getUTCDate()));
}

function adminBucketKey(date, groupBy) {
  return adminBucketStart(date, groupBy).toISOString().slice(0, 10);
}

function nextAdminBucket(date, groupBy) {
  const value = new Date(date);
  if (groupBy === 'month') return new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth() + 1, 1));
  return new Date(value.getTime() + (groupBy === 'week' ? 7 : 1) * 86400000);
}

async function getAdminDashboardAnalytics(req) {
  const { from, toExclusive } = parseAdminAnalyticsRange(req);
  const groupBy = ['day', 'week', 'month'].includes(String(req.query.groupBy || '').toLowerCase())
    ? String(req.query.groupBy).toLowerCase()
    : 'month';

  const dateMatch = { createdAt: { $gte: from, $lt: toExclusive } };
  const [signupDaily, cashInDaily, filteredCashIn, lifetimeCashIn, lifetimeRevenue, filteredRevenue] = await Promise.all([
    User.aggregate([
      { $match: { role: 'user', ...dateMatch } },
      { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt', timezone: 'UTC' } }, count: { $sum: 1 } } },
      { $sort: { _id: 1 } },
    ]),
    Transaction.aggregate([
      { $match: adminCashInMatch() },
      { $addFields: { settlementDate: { $ifNull: ['$metadata.finalizedAt', '$updatedAt'] } } },
      { $match: { settlementDate: { $gte: from, $lt: toExclusive } } },
      { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$settlementDate', timezone: 'UTC' } }, amountCents: { $sum: '$amountCents' }, count: { $sum: 1 } } },
      { $sort: { _id: 1 } },
    ]),
    Transaction.aggregate([
      { $match: adminCashInMatch() },
      { $addFields: { settlementDate: { $ifNull: ['$metadata.finalizedAt', '$updatedAt'] } } },
      { $match: { settlementDate: { $gte: from, $lt: toExclusive } } },
      { $group: { _id: null, amountCents: { $sum: '$amountCents' }, count: { $sum: 1 } } },
    ]),
    Transaction.aggregate([
      { $match: adminCashInMatch() },
      { $group: { _id: null, amountCents: { $sum: '$amountCents' }, count: { $sum: 1 } } },
    ]),
    Transaction.aggregate([
      { $match: adminRevenueMatch() },
      { $group: { _id: null, amountCents: { $sum: '$amountCents' }, count: { $sum: 1 } } },
    ]),
    Transaction.aggregate([
      { $match: adminRevenueMatch() },
      { $addFields: { settlementDate: { $ifNull: ['$metadata.finalizedAt', '$updatedAt'] } } },
      { $match: { settlementDate: { $gte: from, $lt: toExclusive } } },
      { $group: { _id: null, amountCents: { $sum: '$amountCents' }, count: { $sum: 1 } } },
    ]),
  ]);

  const signupMap = new Map(signupDaily.map((item) => [item._id, Number(item.count || 0)]));
  const cashMap = new Map(cashInDaily.map((item) => [item._id, { amountCents: Number(item.amountCents || 0), count: Number(item.count || 0) }]));
  const buckets = [];
  let cursor = adminBucketStart(from, groupBy);
  while (cursor < toExclusive) {
    const next = nextAdminBucket(cursor, groupBy);
    buckets.push({ start: cursor, end: next });
    cursor = next;
  }

  const series = buckets.map((bucket) => {
    let userSignups = 0;
    let cashInCents = 0;
    let cashInCount = 0;
    for (const [key, count] of signupMap.entries()) {
      const day = new Date(`${key}T00:00:00.000Z`);
      if (day >= bucket.start && day < bucket.end) userSignups += count;
    }
    for (const [key, value] of cashMap.entries()) {
      const day = new Date(`${key}T00:00:00.000Z`);
      if (day >= bucket.start && day < bucket.end) {
        cashInCents += value.amountCents;
        cashInCount += value.count;
      }
    }
    return {
      key: bucket.start.toISOString().slice(0, 10),
      label: groupBy === 'month'
        ? bucket.start.toLocaleString('en-GB', { month: 'short', year: 'numeric', timeZone: 'UTC' })
        : groupBy === 'week'
          ? `Week of ${bucket.start.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', timeZone: 'UTC' })}`
          : bucket.start.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', timeZone: 'UTC' }),
      start: bucket.start.toISOString(),
      end: bucket.end.toISOString(),
      userSignups,
      cashInCents,
      cashInCount,
    };
  });

  return {
    range: { from: from.toISOString(), to: new Date(toExclusive.getTime() - 1).toISOString(), groupBy },
    totals: {
      userSignups: signupDaily.reduce((sum, item) => sum + Number(item.count || 0), 0),
      cashInCents: Number(filteredCashIn[0]?.amountCents || 0),
      cashInCount: Number(filteredCashIn[0]?.count || 0),
      revenueCents: Number(filteredRevenue[0]?.amountCents || 0),
      lifetimeCashInCents: Number(lifetimeCashIn[0]?.amountCents || 0),
      lifetimeCashInCount: Number(lifetimeCashIn[0]?.count || 0),
      lifetimeRevenueCents: Number(lifetimeRevenue[0]?.amountCents || 0),
    },
    series,
    definitions: {
      cashIn: 'Completed external Paynow/mock deposits, subscriptions and league entries. Wallet-funded purchases are excluded so they are not counted twice.',
      revenue: 'Completed subscription, league-entry and platform-fee transactions, including wallet-funded purchases.',
    },
  };
}

function requireAdmin(req, res, next) {
  return requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return failure(res, 403, 'Administrator access is required.');
    return next();
  });
}

async function adminAudit(req, action, targetType, targetId, metadata = {}) {
  return AuditLog.create({
    userId: req.user?._id || null,
    action,
    entityType: targetType,
    entityId: targetId ? String(targetId) : '',
    metadata: { ...metadata, adminEmail: req.user?.email || '', ip: req.ip },
  }).catch(() => null);
}

app.post('/api/admin/auth/register', authLimiter, async (req, res, next) => {
  try {
    if (!ADMIN_SIGNUP_KEY || req.body.setupKey !== ADMIN_SIGNUP_KEY) return failure(res, 404, 'Route not found.');
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    if (!req.body.fullName || !/^\S+@\S+\.\S+$/.test(email) || password.length < 12) return failure(res, 400, 'Provide a name, valid email and a password of at least 12 characters.');
    if (await User.exists({ email })) return failure(res, 409, 'An account already exists for this email.');
    const user = await User.create({ fullName: req.body.fullName, email, phone: req.body.phone || 'ADMIN', dateOfBirth: new Date('1990-01-01'), passwordHash: await bcrypt.hash(password, 12), role: 'admin', ageConfirmed: true, status: 'active' });
    await ensureUserResources(user._id);
    await adminAudit({ user, ip: req.ip }, 'admin.registered', 'User', user._id);
    await Promise.all([emailService.notifyAdminWelcome(user), emailService.notifyOwnerAdminSignup(user)]);
    return success(res, { admin: adminPublicUser(user) }, 201);
  } catch (error) { next(error); }
});

app.post('/api/admin/auth/login', authLimiter, async (req, res, next) => {
  try {
    const user = await User.findOne({ email: normalizeEmail(req.body.email), role: 'admin' }).select('+passwordHash');
    if (!user || !(await bcrypt.compare(String(req.body.password || ''), user.passwordHash))) return failure(res, 401, 'Invalid administrator credentials.');
    if (user.status !== 'active') return failure(res, 403, 'This administrator account is not active.');
    const token = jwt.sign({ sub: String(user._id) }, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    res.cookie(COOKIE_NAME, token, { httpOnly: true, sameSite: IS_PRODUCTION ? 'none' : 'lax', secure: IS_PRODUCTION, maxAge: 7 * 24 * 60 * 60 * 1000 });
    await adminAudit({ user, ip: req.ip }, 'admin.login', 'User', user._id);
    return success(res, { admin: adminPublicUser(user) });
  } catch (error) { next(error); }
});

app.get('/api/admin/session', requireAdmin, (req, res) => success(res, { admin: adminPublicUser(req.user) }));

app.get('/api/admin/dashboard', requireAdmin, async (req, res, next) => {
  try {
    const monthStart = new Date(); monthStart.setUTCDate(1); monthStart.setUTCHours(0, 0, 0, 0);
    const [users, newUsers, activeSubscriptions, usersInLeagues, leagueGroups, activeLeagues, finance, openTickets, analytics] = await Promise.all([
      User.countDocuments({ role: 'user' }),
      User.countDocuments({ role: 'user', createdAt: { $gte: monthStart } }),
      Subscription.countDocuments({ status: 'active' }),
      LeagueEntry.distinct('userId').then((x) => x.length),
      League.aggregate([{ $group: { _id: '$competitionType', count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
      League.countDocuments({ status: { $in: ['open', 'upcoming', 'live'] } }),
      Transaction.aggregate([{ $match: { status: 'completed' } }, { $group: { _id: { type: '$type', direction: '$direction', provider: '$provider' }, amountCents: { $sum: '$amountCents' }, count: { $sum: 1 } } }]),
      SupportTicket.countDocuments({ status: { $nin: ['resolved', 'closed'] } }),
      getAdminDashboardAnalytics(req),
    ]);
    const payoutsDueCents = await Transaction.aggregate([
      { $match: { type: { $in: ['withdrawal', 'prize'] }, status: { $in: ['pending', 'processing'] } } },
      { $group: { _id: null, total: { $sum: '$amountCents' } } },
    ]).then((x) => x[0]?.total || 0);
    return success(res, {
      users,
      newUsers,
      activeSubscriptions,
      usersInLeagues,
      leagues: { total: leagueGroups.reduce((sum, item) => sum + item.count, 0), active: activeLeagues, byType: leagueGroups },
      finances: {
        // Dashboard financial figures use the default 30-calendar-month
        // reporting window rather than an arbitrary current-month slice.
        revenueCents: analytics.totals.revenueCents,
        cashInCents: analytics.totals.cashInCents,
        collectedCents: analytics.totals.cashInCents,
        lifetimeRevenueCents: analytics.totals.lifetimeRevenueCents,
        lifetimeCashInCents: analytics.totals.lifetimeCashInCents,
        payoutsDueCents,
        breakdown: finance,
      },
      analytics,
      openTickets,
    });
  } catch (error) { next(error); }
});

app.get('/api/admin/dashboard/analytics', requireAdmin, async (req, res, next) => {
  try {
    return success(res, await getAdminDashboardAnalytics(req));
  } catch (error) { next(error); }
});

async function getLeagueSettlementDiagnostics(leagueId, { verifyLive = true } = {}) {
  const league = await League.findById(leagueId).lean();
  if (!league) return null;
  if (league.officialSupremeLeague) {
    const supreme = await localGrowth.getSettlementDiagnostics(leagueId, { verifyLive });
    if (supreme) return { type: 'supreme', ...supreme };
  }
  let verified = null;
  if (verifyLive && FPL_DATA_MODE === 'public') {
    try {
      verified = await getVerifiedFplRangeState(league.startGameweek, league.endGameweek);
    } catch (error) {
      verified = { finished: false, dataChecked: false, reason: error.message, schedules: [] };
    }
  }
  const entries = await LeagueEntry.find({ leagueId }).select('paymentStatus eligibilityStatus scoreSyncStatus scoreSyncError currentScore currentRank fantasyManagerId payoutStatus prizeCents').lean();
  const eligible = entries.filter((entry) => ['paid', 'completed'].includes(entry.paymentStatus) && entry.eligibilityStatus !== 'ineligible');
  return {
    type: 'standard',
    verified: verified ? {
      finished: verified.finished,
      dataChecked: verified.dataChecked,
      reason: verified.reason,
      fixtureStates: (verified.schedules || []).map((schedule) => ({ gameweek: schedule.gameweek, eventFinished: schedule.eventFinished, fixturesFinished: schedule.fixturesFinished, fixtureCount: schedule.fixtureCount, dataChecked: schedule.dataChecked })),
    } : null,
    participants: entries.length,
    eligibleParticipants: eligible.length,
    successfullyScored: eligible.filter((entry) => entry.scoreSyncStatus === 'success').length,
    scoreFailures: eligible.filter((entry) => entry.scoreSyncStatus === 'failed').map((entry) => entry.scoreSyncError).filter(Boolean),
    readyForAutomaticSettlement: Boolean(verified?.finished && verified?.dataChecked && eligible.length),
    canManualSettle: Boolean(verified?.finished && eligible.length),
  };
}

async function settleStandardLeagueFromAdmin(leagueId, { adminUserId, reason, forceDataChecked = false } = {}) {
  const league = await League.findById(leagueId);
  if (!league) { const error = new Error('League not found.'); error.status = 404; throw error; }
  if (league.officialSupremeLeague) {
    return localGrowth.settleLeagueById(leagueId, { manualBy: adminUserId, reason, forceDataChecked });
  }
  if (league.status === 'settled') return { settled: true, alreadySettled: true };
  if (FPL_DATA_MODE !== 'public') { const error = new Error('Manual settlement requires FPL_DATA_MODE=public.'); error.status = 409; throw error; }
  const verified = await getVerifiedFplRangeState(league.startGameweek, league.endGameweek);
  if (!verified.finished) { const error = new Error('FPL has not verified that all included gameweeks and fixtures are finished.'); error.status = 409; throw error; }
  if (!verified.dataChecked && !forceDataChecked) { const error = new Error('FPL has finished the football, but data_checked is still false. Use the explicit manual override only after reviewing the scores.'); error.status = 409; throw error; }

  await syncLeagueScores(league._id, { force: true });
  const entries = await LeagueEntry.find({ leagueId: league._id, paymentStatus: { $in: ['paid', 'completed'] }, eligibilityStatus: { $ne: 'ineligible' } });
  if (!entries.length) { const error = new Error('There are no eligible paid entries to settle.'); error.status = 409; throw error; }
  const failed = entries.filter((entry) => entry.scoreSyncStatus === 'failed');
  if (failed.length) { const error = new Error(`${failed.length} eligible entr${failed.length === 1 ? 'y' : 'ies'} could not be scored from FPL.`); error.status = 409; throw error; }
  entries.sort((a, b) => Number(b.currentScore || 0) - Number(a.currentScore || 0) || new Date(a.joinedAt || 0) - new Date(b.joinedAt || 0));
  let lastScore = null; let rank = 0;
  entries.forEach((entry, index) => { if (lastScore === null || Number(entry.currentScore) !== Number(lastScore)) rank = index + 1; entry.currentRank = rank; lastScore = entry.currentScore; });
  const topScore = Number(entries[0].currentScore || 0);
  const winners = entries.filter((entry) => Number(entry.currentScore || 0) === topScore);
  const totalPrize = Math.max(0, Number(league.displayedPrizeCents || league.projectedPrizeCents || Math.max(0, Number(league.grossPoolCents || 0))));
  const base = winners.length ? Math.floor(totalPrize / winners.length) : 0;
  let remainder = totalPrize - base * winners.length;
  const winnerIds = new Set(winners.map((entry) => String(entry.userId)));
  for (const entry of entries) {
    if (winnerIds.has(String(entry.userId))) {
      const amount = base + (remainder > 0 ? 1 : 0); if (remainder > 0) remainder -= 1;
      entry.prizeCents = amount; entry.payoutStatus = 'paid';
      if (amount > 0) {
        const reference = `ADMIN-PRIZE-${league._id}-${entry.userId}`;
        await Transaction.findOneAndUpdate({ reference }, { $setOnInsert: { userId: entry.userId, leagueId: league._id, reference, type: 'prize', direction: 'credit', amountCents: amount, currency: 'USD', provider: 'admin-settlement', status: 'completed', description: `Prize for ${league.name}`, metadata: { purpose: 'manual-league-settlement', reason: String(reason || ''), adminUserId: String(adminUserId || '') } } }, { upsert: true, new: true });
        await updateWalletBalances(entry.userId, { availableBalanceCents: amount, lifetimePrizesCents: amount }, `Manual league settlement ${reference}`, 'settleStandardLeagueFromAdmin', {}, `${reference}:wallet-credit`);
      }
    } else {
      entry.prizeCents = 0; entry.payoutStatus = 'not-applicable';
    }
    await entry.save();
  }
  const now = new Date();
  league.status = 'settled'; league.completedAt = league.fplFinishedAt || now; league.expiresAt = league.fplFinishedAt || now; league.fplFinishedAt = league.fplFinishedAt || now;
  if (verified.dataChecked) league.fplDataCheckedAt = league.fplDataCheckedAt || now;
  await league.save();
  await emailService.notifyLeagueOutcomes(league._id);
  return { settled: true, winners: winners.length, prizeCents: totalPrize, manual: true };
}

app.get('/api/admin/leagues', requireAdmin, async (req, res, next) => {
  try {
    const { page, limit } = pageOptions(req); const search = String(req.query.search || '').trim();
    const filter = {};
    if (search) filter.$or = [{ name: new RegExp(escapeRegex(search), 'i') }, { competitionType: new RegExp(escapeRegex(search), 'i') }, { status: new RegExp(escapeRegex(search), 'i') }];
    if (req.query.status) filter.status = req.query.status;
    if (req.query.type) filter.competitionType = req.query.type;
    const [rows,total] = await Promise.all([League.find(filter).sort({ createdAt:-1 }).skip((page-1)*limit).limit(limit).lean(), League.countDocuments(filter)]);
    const ids=rows.map(x=>x._id); const counts=await LeagueEntry.aggregate([{ $match:{leagueId:{$in:ids}}},{ $group:{_id:'$leagueId',members:{$sum:1}}}]); const map=new Map(counts.map(x=>[String(x._id),x.members]));
    return success(res,{rows:rows.map(x=>({...x,memberCount:map.get(String(x._id))||0,expiresAt:x.expiresAt})),pagination:{page,limit,total,pages:Math.ceil(total/limit)}});
  } catch(error){next(error);}
});

app.get('/api/admin/leagues/:id', requireAdmin, async (req, res, next) => {
  try {
    const refreshRequested = String(req.query.refresh || '') === '1';
    const base = await League.findById(req.params.id).lean();
    if (!base) return failure(res, 404, 'League not found.');
    if (refreshRequested) {
      await refreshLeagueLifecycleIfStale();
      if (base.officialSupremeLeague) {
        await localGrowth.settleLeagueById(base._id, { trigger: 'admin-league-page' }).catch((error) => {
          if (Number(error.status || 500) >= 500) console.error('Admin opportunistic Supreme settlement failed:', error.message);
        });
      }
      await syncLeagueScores(base._id, { force: false }).catch((error) => console.warn('Admin league score refresh failed:', error.message));
    }
    const [league, members, settlement] = await Promise.all([
      League.findById(req.params.id).populate('createdBy', 'fullName email').lean(),
      LeagueEntry.find({ leagueId: req.params.id }).populate('userId', 'fullName email phone status fantasyTeamName').sort({ currentRank: 1, joinedAt: 1 }).lean(),
      getLeagueSettlementDiagnostics(req.params.id, { verifyLive: refreshRequested }),
    ]);
    return success(res, { league, members, settlement, leaderboard: members.map((m) => ({ entryId: m._id, user: m.userId, rank: m.currentRank, score: m.currentScore, scoreDetails: m.scoreDetails || {}, prizeCents: m.prizeCents, payoutStatus: m.payoutStatus, joinedAt: m.joinedAt, eligibilityStatus: m.eligibilityStatus })) });
  } catch (error) { next(error); }
});

app.patch('/api/admin/leagues/:id/status', requireAdmin, writeLimiter, async (req, res, next) => {
  try {
    const allowed = ['draft', 'open', 'full', 'upcoming', 'live', 'awaiting-review', 'cancelled'];
    if (req.body.status === 'settled') return failure(res, 409, 'Use the settlement controls to settle a league. Settlement must calculate scores and credit prizes; a status change alone is not settlement.');
    if (!allowed.includes(req.body.status)) return failure(res, 400, 'Invalid league status.');
    const league = await League.findByIdAndUpdate(req.params.id, { $set: { status: req.body.status } }, { new: true });
    if (!league) return failure(res, 404, 'League not found.');
    await adminAudit(req, 'league.status.updated', 'League', league._id, { status: req.body.status });
    return success(res, { league });
  } catch (error) { next(error); }
});

app.post('/api/admin/leagues/:id/refresh-scores', requireAdmin, writeLimiter, async (req, res, next) => {
  try {
    const league = await League.findById(req.params.id);
    if (!league) return failure(res, 404, 'League not found.');
    await refreshLeagueLifecycleIfStale();
    const synced = await syncLeagueScores(league._id, { force: true });
    return success(res, { synced, settlement: await getLeagueSettlementDiagnostics(league._id) });
  } catch (error) { next(error); }
});

app.post('/api/admin/leagues/:id/settlement/retry', requireAdmin, writeLimiter, async (req, res, next) => {
  try {
    const league = await League.findById(req.params.id);
    if (!league) return failure(res, 404, 'League not found.');
    let result;
    if (league.officialSupremeLeague) result = await localGrowth.settleLeagueById(league._id, { manualBy: req.user._id, reason: 'Administrator requested automatic settlement retry' });
    else result = await settleStandardLeagueFromAdmin(league._id, { adminUserId: req.user._id, reason: 'Administrator requested automatic settlement retry', forceDataChecked: false });
    await adminAudit(req, 'league.settlement.retry', 'League', league._id, { result });
    return success(res, { result, settlement: await getLeagueSettlementDiagnostics(league._id) });
  } catch (error) { next(error); }
});

app.post('/api/admin/leagues/:id/settlement/manual', requireAdmin, writeLimiter, async (req, res, next) => {
  try {
    const reason = String(req.body.reason || '').trim().slice(0, 500);
    if (!reason) return failure(res, 400, 'Provide a reason for the manual settlement override.');
    const league = await League.findById(req.params.id);
    if (!league) return failure(res, 404, 'League not found.');
    // Manual override can bypass data_checked after an administrator reviews the
    // leaderboard, but it can NEVER bypass the verified football-finished check.
    const result = league.officialSupremeLeague
      ? await localGrowth.settleLeagueById(league._id, { manualBy: req.user._id, reason, forceDataChecked: true })
      : await settleStandardLeagueFromAdmin(league._id, { adminUserId: req.user._id, reason, forceDataChecked: true });
    await adminAudit(req, 'league.settlement.manual', 'League', league._id, { reason, result });
    return success(res, { result, settlement: await getLeagueSettlementDiagnostics(league._id) });
  } catch (error) { next(error); }
});

app.post('/api/admin/leagues/:id/members', requireAdmin, writeLimiter, async (req, res, next) => {
  try {
    const user = await User.findOne(req.body.userId ? { _id: req.body.userId } : { email: normalizeEmail(req.body.email) });
    if (!user) return failure(res, 404, 'User not found.');
    const paymentStatus = ['pending', 'paid', 'failed', 'refunded'].includes(req.body.paymentStatus) ? req.body.paymentStatus : 'paid';
    const entry = await LeagueEntry.findOneAndUpdate(
      { leagueId: req.params.id, userId: user._id },
      { $setOnInsert: { fantasyManagerId: user.fplManagerId, joinedAt: new Date(), paymentStatus } },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );
    await adminAudit(req, 'league.member.added', 'League', req.params.id, { userId: user._id });
    if (entry.paymentStatus === 'paid') {
      await emailService.notifyLeagueMembership(user._id, req.params.id, 'administrator addition');
    }
    return success(res, { entry }, 201);
  } catch (error) {
    if (error.code === 11000) return failure(res, 409, 'User is already a member.');
    next(error);
  }
});

app.delete('/api/admin/leagues/:id/members/:userId', requireAdmin, writeLimiter, async(req,res,next)=>{try{const entry=await LeagueEntry.findOneAndDelete({leagueId:req.params.id,userId:req.params.userId}); if(!entry)return failure(res,404,'League member not found.'); await adminAudit(req,'league.member.removed','League',req.params.id,{userId:req.params.userId}); return success(res,{removed:true});}catch(error){next(error);}});

app.get('/api/admin/users', requireAdmin, async(req,res,next)=>{try{
  const {page,limit}=pageOptions(req); const search=String(req.query.search||'').trim(); const filter={role:'user'}; if(search)filter.$or=[{fullName:new RegExp(escapeRegex(search),'i')},{email:new RegExp(escapeRegex(search),'i')},{phone:new RegExp(escapeRegex(search),'i')}]; if(req.query.status)filter.status=req.query.status;
  const [rows,total]=await Promise.all([User.find(filter).sort({createdAt:-1}).skip((page-1)*limit).limit(limit).lean(),User.countDocuments(filter)]); const ids=rows.map(x=>x._id);
  const [subs,entries,wallets]=await Promise.all([Subscription.find({userId:{$in:ids},status:'active'}).lean(),LeagueEntry.aggregate([{ $match:{userId:{$in:ids}}},{ $group:{_id:'$userId',count:{$sum:1}}}]),Wallet.find({userId:{$in:ids}}).lean()]);
  const sm=new Map(subs.map(x=>[String(x.userId),x])); const em=new Map(entries.map(x=>[String(x._id),x.count])); const wm=new Map(wallets.map(x=>[String(x.userId),x])); return success(res,{rows:rows.map(u=>({...adminPublicUser(u),subscription:sm.get(String(u._id))||null,leagueCount:em.get(String(u._id))||0,wallet:wm.get(String(u._id))||null})),pagination:{page,limit,total,pages:Math.ceil(total/limit)}});
}catch(error){next(error);}});

app.get('/api/admin/users/:id', requireAdmin, async (req, res, next) => {
  try {
    const refreshRequested = String(req.query.refresh || '') === '1';
    const userDoc = await User.findById(req.params.id);
    if (!userDoc) return failure(res, 404, 'User not found.');
    let team = null;
    if (userDoc.fplManagerId) {
      if (refreshRequested) {
        await Promise.allSettled([
          persistFantasyTeamSnapshot(userDoc, { force: false }),
          syncUserLeagueScores(userDoc._id, { force: false, limit: 8 }),
        ]);
      }
      team = await buildTeamPayload(userDoc, { refresh: false }).catch((error) => ({ error: error.message, providerMode: FPL_DATA_MODE }));
    }
    const [user, profile, wallet, subscriptions, entries, transactions] = await Promise.all([
      User.findById(req.params.id).lean(), UserProfile.findOne({ userId: req.params.id }).lean(), Wallet.findOne({ userId: req.params.id }).lean(),
      Subscription.find({ userId: req.params.id }).sort({ createdAt: -1 }).lean(),
      LeagueEntry.find({ userId: req.params.id }).populate('leagueId', 'name competitionType status').sort({ joinedAt: -1 }).lean(),
      Transaction.find({ userId: req.params.id }).sort({ createdAt: -1 }).limit(200).lean(),
    ]);
    return success(res, { user, profile, wallet, subscriptions, entries, transactions, team });
  } catch (error) { next(error); }
});

app.patch('/api/admin/users/:id/status', requireAdmin, writeLimiter, async(req,res,next)=>{try{if(!['active','suspended','closed'].includes(req.body.status))return failure(res,400,'Invalid user status.'); const user=await User.findOneAndUpdate({_id:req.params.id,role:'user'},{$set:{status:req.body.status}},{new:true}); if(!user)return failure(res,404,'User not found.'); await adminAudit(req,'user.status.updated','User',user._id,{status:req.body.status}); return success(res,{user:adminPublicUser(user)});}catch(error){next(error);}});

// Cancels a subscription that was created too late for the cycle it targeted
// (e.g. a league joined after its cutoff) and refunds the paid amount back to
// the member's Supreme wallet as a completed 'refund' transaction. Sends the
// member a branded email confirming the cancellation and refund.
app.post('/api/admin/subscriptions/:id/cancel-refund', requireAdmin, writeLimiter, async (req, res, next) => {
  try {
    const subscription = await Subscription.findById(req.params.id);
    if (!subscription) return failure(res, 404, 'Subscription not found.');
    if (subscription.status === 'cancelled') return failure(res, 409, 'This subscription has already been cancelled.');

    const reason = String(req.body.reason || '').trim().slice(0, 500);
    if (!reason) return failure(res, 400, 'Provide a reason for cancelling this subscription.');

    const originalAmountCents = Number(subscription.amountCents || 0);
    const requestedRefundCents = req.body.refundAmountCents !== undefined
      ? Math.round(Number(req.body.refundAmountCents))
      : originalAmountCents;
    if (!Number.isFinite(requestedRefundCents) || requestedRefundCents < 0 || requestedRefundCents > originalAmountCents) {
      return failure(res, 400, `Refund amount must be between $0.00 and $${(originalAmountCents / 100).toFixed(2)}.`);
    }

    const now = new Date();
    subscription.status = 'cancelled';
    subscription.endDate = now;
    subscription.validUntil = now;
    subscription.lastValidityCheckAt = now;
    subscription.cancelledAt = now;
    subscription.cancelledBy = req.user._id;
    subscription.cancellationReason = reason;
    await subscription.save();

    let transaction = null;
    if (requestedRefundCents > 0) {
      const reference = createReference('ADMR');
      transaction = await Transaction.create({
        userId: subscription.userId,
        subscriptionId: subscription._id,
        reference,
        type: 'refund',
        direction: 'credit',
        amountCents: requestedRefundCents,
        currency: 'USD',
        provider: 'admin',
        status: 'completed',
        description: `${subscription.planName || 'Subscription'} cancelled by admin — refunded to wallet`,
        metadata: { reason, adminId: String(req.user._id), subscriptionId: String(subscription._id) },
      });
      await updateWalletBalances(
        subscription.userId,
        {
          availableBalanceCents: requestedRefundCents,
          lifetimeSubscriptionFeesCents: -requestedRefundCents,
          lifetimeRefundsCents: requestedRefundCents,
        },
        `Subscription cancelled by admin — refunded ${reference}`,
        'adminCancelSubscriptionRefund',
        {},
        `${reference}:admin-credit`
      );
      await emailService.notifyAdminWalletAdjustment(transaction);
    }

    await adminAudit(req, 'subscription.cancelled.refunded', 'Subscription', subscription._id, {
      reason,
      refundCents: requestedRefundCents,
      userId: String(subscription.userId),
    });

    const wallet = await Wallet.findOne({ userId: subscription.userId }).lean();
    return success(res, { subscription: subscription.toObject(), wallet, transaction });
  } catch (error) { next(error); }
});

// Admin-awarded performance bonus. The amount is credited to the member's
// available/withdrawable wallet balance, recorded as an auditable adjustment,
// and the member receives an email with the amount and reason.
app.post('/api/admin/users/:id/performance-bonus', requireAdmin, writeLimiter, async (req, res, next) => {
  try {
    const user = await User.findOne({ _id: req.params.id, role: 'user' });
    if (!user) return failure(res, 404, 'User not found.');
    const reason = String(req.body.reason || '').trim().slice(0, 500);
    if (!reason) return failure(res, 400, 'Provide the performance achievement or reason for this bonus.');
    const amountCents = Math.round(Number(req.body.amountCents));
    if (!Number.isFinite(amountCents) || amountCents <= 0) return failure(res, 400, 'Provide a bonus amount greater than $0.00.');
    await ensureUserResources(user._id);
    const reference = createReference('BONUS');
    const transaction = await Transaction.create({
      userId: user._id, reference, type: 'adjustment', direction: 'credit', amountCents, currency: 'USD', provider: 'admin-performance-bonus', status: 'completed',
      description: `Performance bonus — ${reason}`,
      metadata: { purpose: 'performance-bonus', reason, adminId: String(req.user._id) },
    });
    await updateWalletBalances(user._id, { availableBalanceCents: amountCents, lifetimeAdjustmentsCents: amountCents }, `Performance bonus ${reference}`, 'adminPerformanceBonus', {}, `${reference}:wallet-credit`);
    await emailService.notifyPerformanceBonus(transaction);
    await adminAudit(req, 'performance-bonus.awarded', 'User', user._id, { amountCents, reason, reference });
    const wallet = await Wallet.findOne({ userId: user._id }).lean();
    return success(res, { wallet, transaction }, 201);
  } catch (error) { next(error); }
});

app.post('/api/admin/users/:id/wallet/credit', requireAdmin, writeLimiter, async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return failure(res, 404, 'User not found.');

    const reason = String(req.body.reason || '').trim().slice(0, 500);
    if (!reason) return failure(res, 400, 'Provide a reason for this wallet credit.');

    const amountCents = Math.round(Number(req.body.amountCents));
    if (!Number.isFinite(amountCents) || amountCents <= 0) {
      return failure(res, 400, 'Provide a credit amount greater than $0.00.');
    }

    await ensureUserResources(user._id);
    const reference = createReference('ADMC');
    const transaction = await Transaction.create({
      userId: user._id,
      reference,
      type: 'adjustment',
      direction: 'credit',
      amountCents,
      currency: 'USD',
      provider: 'admin',
      status: 'completed',
      description: `Wallet credited by admin — ${reason}`,
      metadata: { reason, adminId: String(req.user._id) },
    });

    await updateWalletBalances(
      user._id,
      { availableBalanceCents: amountCents, lifetimeAdjustmentsCents: amountCents },
      `Admin wallet credit ${reference}`,
      'adminCreditWallet',
      {},
      `${reference}:admin-credit`
    );

    await emailService.notifyAdminWalletAdjustment(transaction);
    await adminAudit(req, 'wallet.credited', 'User', user._id, { amountCents, reason });

    const wallet = await Wallet.findOne({ userId: user._id }).lean();
    return success(res, { wallet, transaction });
  } catch (error) { next(error); }
});

app.get('/api/admin/transactions', requireAdmin, async (req, res, next) => {
  try {
    const { page, limit } = pageOptions(req, 50);
    const { from, toExclusive } = parseAdminAnalyticsRange(req);
    const filter = {
      createdAt: { $gte: from, $lt: toExclusive },
    };

    if (req.query.type) filter.type = req.query.type;
    if (req.query.status) filter.status = req.query.status;
    if (req.query.provider) filter.provider = req.query.provider;
    if (req.query.direction) filter.direction = req.query.direction;

    if (req.query.minAmount) {
      filter.amountCents = {
        ...(filter.amountCents || {}),
        $gte: Math.round(Number(req.query.minAmount) * 100),
      };
    }

    if (req.query.maxAmount) {
      filter.amountCents = {
        ...(filter.amountCents || {}),
        $lte: Math.round(Number(req.query.maxAmount) * 100),
      };
    }

    if (req.query.search) {
      filter.$or = [
        { reference: new RegExp(escapeRegex(req.query.search), 'i') },
        { description: new RegExp(escapeRegex(req.query.search), 'i') },
      ];
    }

    // Period totals intentionally ignore row-level filters such as search,
    // purpose and provider. The date range is the reporting boundary, so the
    // admin can filter the transaction table without making money disappear
    // from the headline cash/revenue figures.

    const [rows, total, summary, cashIn, revenue, revenueBreakdown, payoutsDue] = await Promise.all([
      Transaction.find(filter)
        .populate('userId', 'fullName email phone')
        .populate('leagueId', 'name')
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Transaction.countDocuments(filter),
      Transaction.aggregate([
        { $match: filter },
        {
          $group: {
            _id: {
              type: '$type',
              status: '$status',
              provider: '$provider',
              direction: '$direction',
            },
            amountCents: { $sum: '$amountCents' },
            count: { $sum: 1 },
          },
        },
      ]),
      Transaction.aggregate([
        { $match: adminCashInMatch() },
        {
          $addFields: {
            settlementDate: { $ifNull: ['$metadata.finalizedAt', '$updatedAt'] },
          },
        },
        { $match: { settlementDate: { $gte: from, $lt: toExclusive } } },
        {
          $group: {
            _id: null,
            amountCents: { $sum: '$amountCents' },
            count: { $sum: 1 },
          },
        },
      ]),
      Transaction.aggregate([
        { $match: adminRevenueMatch() },
        {
          $addFields: {
            settlementDate: { $ifNull: ['$metadata.finalizedAt', '$updatedAt'] },
          },
        },
        { $match: { settlementDate: { $gte: from, $lt: toExclusive } } },
        {
          $group: {
            _id: null,
            amountCents: { $sum: '$amountCents' },
            count: { $sum: 1 },
          },
        },
      ]),
      Transaction.aggregate([
        { $match: adminRevenueMatch() },
        {
          $addFields: {
            settlementDate: { $ifNull: ['$metadata.finalizedAt', '$updatedAt'] },
          },
        },
        { $match: { settlementDate: { $gte: from, $lt: toExclusive } } },
        {
          $group: {
            _id: '$type',
            amountCents: { $sum: '$amountCents' },
            count: { $sum: 1 },
          },
        },
      ]),
      Transaction.aggregate([
        {
          $match: {
            type: { $in: ['withdrawal', 'prize'] },
            status: { $in: ['pending', 'processing'] },
          },
        },
        {
          $group: {
            _id: null,
            amountCents: { $sum: '$amountCents' },
            count: { $sum: 1 },
          },
        },
      ]),
    ]);

    return success(res, {
      rows,
      summary,
      cashIn: {
        amountCents: Number(cashIn[0]?.amountCents || 0),
        count: Number(cashIn[0]?.count || 0),
      },
      revenue: {
        amountCents: Number(revenue[0]?.amountCents || 0),
        count: Number(revenue[0]?.count || 0),
      },
      revenueBreakdown: revenueBreakdown.map((item) => ({
        type: item._id,
        amountCents: Number(item.amountCents || 0),
        count: Number(item.count || 0),
      })),
      payoutsDue: {
        amountCents: Number(payoutsDue[0]?.amountCents || 0),
        count: Number(payoutsDue[0]?.count || 0),
      },
      range: {
        from: from.toISOString(),
        to: new Date(toExclusive.getTime() - 1).toISOString(),
      },
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/admin/transactions/:id', requireAdmin, async(req,res,next)=>{try{const transaction=await Transaction.findById(req.params.id).populate('userId','fullName email phone').populate('leagueId','name competitionType').populate('subscriptionId').lean();if(!transaction)return failure(res,404,'Transaction not found.');return success(res,{transaction});}catch(error){next(error);}});
app.patch('/api/admin/withdrawals/:id/status', requireAdmin, writeLimiter, async (req, res, next) => {
  try {
    const nextStatus = String(req.body.status || '').trim();
    if (!['processing', 'completed', 'rejected', 'cancelled'].includes(nextStatus)) return failure(res, 400, 'Invalid withdrawal status.');
    const allowedFrom = nextStatus === 'processing' ? ['pending'] : ['pending', 'processing'];
    const withdrawal = await Transaction.findOneAndUpdate(
      { _id: req.params.id, type: 'withdrawal', status: { $in: allowedFrom } },
      { $set: { status: nextStatus, 'metadata.adminNote': String(req.body.note || '').slice(0, 500), 'metadata.reviewedBy': req.user._id, 'metadata.reviewedAt': new Date(), ...(nextStatus === 'completed' ? { 'metadata.paidAt': new Date() } : {}) } },
      { new: true }
    );
    if (!withdrawal) return failure(res, 409, 'This withdrawal has already moved from its current state. Refresh and try again.');
    if (nextStatus === 'completed') {
      await updateWalletBalances(withdrawal.userId, { pendingBalanceCents: -withdrawal.amountCents, lifetimeWithdrawalsCents: withdrawal.amountCents }, `withdrawal-paid:${withdrawal.reference}`, 'adminWithdrawalStatusEndpoint', {}, `${withdrawal.reference}:paid`);
    } else if (['rejected', 'cancelled'].includes(nextStatus)) {
      await updateWalletBalances(withdrawal.userId, { pendingBalanceCents: -withdrawal.amountCents, availableBalanceCents: withdrawal.amountCents }, `withdrawal-released:${withdrawal.reference}`, 'adminWithdrawalStatusEndpoint', {}, `${withdrawal.reference}:released`);
    }
    await adminAudit(req, 'withdrawal.status.updated', 'Transaction', withdrawal._id, { status: nextStatus, reference: withdrawal.reference });
    await emailService.notifyPaymentUpdate(withdrawal);
    return success(res, { transaction: await Transaction.findById(withdrawal._id).populate('userId','fullName email phone').lean() });
  } catch (error) { next(error); }
});

app.get('/api/admin/tickets', requireAdmin, async(req,res,next)=>{try{const {page,limit}=pageOptions(req);const filter={};if(req.query.status)filter.status=req.query.status;if(req.query.priority)filter.priority=req.query.priority;if(req.query.category)filter.category=req.query.category;if(req.query.search)filter.$or=[{ticketNumber:new RegExp(escapeRegex(req.query.search),'i')},{subject:new RegExp(escapeRegex(req.query.search),'i')},{message:new RegExp(escapeRegex(req.query.search),'i')}];const [rows,total]=await Promise.all([SupportTicket.find(filter).populate('userId','fullName email').populate('assignedTo','fullName email').populate('closedBy','fullName email').sort({lastActivityAt:-1}).skip((page-1)*limit).limit(limit).lean(),SupportTicket.countDocuments(filter)]);return success(res,{rows,pagination:{page,limit,total,pages:Math.ceil(total/limit)}});}catch(error){next(error);}});
app.get('/api/admin/tickets/:id', requireAdmin, async(req,res,next)=>{try{const ticket=await SupportTicket.findById(req.params.id).populate('userId','fullName email phone').populate('assignedTo','fullName email').populate('closedBy','fullName email').populate('responses.authorId','fullName email').lean();if(!ticket)return failure(res,404,'Ticket not found.');return success(res,{ticket});}catch(error){next(error);}});
app.patch('/api/admin/tickets/:id', requireAdmin, writeLimiter, async(req,res,next)=>{try{const ticket=await SupportTicket.findById(req.params.id);if(!ticket)return failure(res,404,'Ticket not found.');if(req.body.status){if(!['open','in-progress','waiting-user','resolved','closed'].includes(req.body.status))return failure(res,400,'Invalid ticket status.');ticket.status=req.body.status;if(req.body.status==='closed'){ticket.closedBy=req.user._id;ticket.closedAt=new Date();}else if(ticket.closedAt){ticket.closedBy=null;ticket.closedAt=null;}}if(req.body.priority)ticket.priority=req.body.priority;if(req.body.assignedTo!==undefined)ticket.assignedTo=req.body.assignedTo||null;if(req.body.response)ticket.responses.push({authorId:req.user._id,authorRole:'admin',message:req.body.response});ticket.lastActivityAt=new Date();await ticket.save();await adminAudit(req,'ticket.updated','SupportTicket',ticket._id,{status:ticket.status});return success(res,{ticket});}catch(error){next(error);}});

// -----------------------------------------------------------------------------
// Optional demo-account seed
// -----------------------------------------------------------------------------
async function ensureDemoUser() {
  const email = normalizeEmail(process.env.DEMO_USER_EMAIL);
  const password = String(process.env.DEMO_USER_PASSWORD || '');

  if (!email && !password) return null;
  if (!email || !password) {
    throw new Error('DEMO_USER_EMAIL and DEMO_USER_PASSWORD must either both be set or both be left blank.');
  }
  if (!/^\S+@\S+\.\S+$/.test(email)) {
    throw new Error('DEMO_USER_EMAIL must be a valid email address.');
  }
  if (password.length < 8) {
    throw new Error('DEMO_USER_PASSWORD must be at least 8 characters.');
  }

  let user = await User.findOne({ email }).select('+passwordHash');
  if (!user) {
    user = await User.create({
      fullName: 'Supreme Demo User',
      email,
      phone: '+263771234567',
      dateOfBirth: new Date('1990-01-01T00:00:00.000Z'),
      passwordHash: await bcrypt.hash(password, 12),
      ageConfirmed: true,
      status: 'active',
    });
    console.log(`Demo account created for ${email}`);
  } else {
    const passwordMatches = await bcrypt.compare(password, user.passwordHash);
    const updates = {};
    if (!passwordMatches) updates.passwordHash = await bcrypt.hash(password, 12);
    if (user.status !== 'active') updates.status = 'active';

    if (Object.keys(updates).length) {
      user = await User.findByIdAndUpdate(user._id, { $set: updates }, { new: true }).select('+passwordHash');
      console.log(`Demo account credentials synchronised for ${email}`);
    }
  }

  await ensureUserResources(user._id);
  return user;
}

// -----------------------------------------------------------------------------
// Seed demo leagues. This adds discoverable competitions without creating users.
// -----------------------------------------------------------------------------
async function ensureDemoLeagues() {
  const count = await League.countDocuments({ officialSupremeLeague: true });
  if (count) return;
  const seed = [
    { name: 'Supreme Weekly Cup', description: 'A focused one-gameweek competition with published scoring rules.', competitionType: 'weekly', cadence: 'weekly', startGameweek: 12, endGameweek: 12, entryFeeCents: 200, displayedPrizeCents: 1000, projectedPrizeCents: 1000, guaranteedPrize: true, prizeType: 'guaranteed', minimumParticipants: 2, maximumParticipants: 100 },
    { name: 'Supreme Bi-Weekly Cup', description: 'Highest cumulative qualifying score across two gameweeks.', competitionType: 'best-of-three', cadence: 'bi-weekly', startGameweek: 12, endGameweek: 13, entryFeeCents: 300, displayedPrizeCents: 1500, projectedPrizeCents: 1500, guaranteedPrize: false, prizeType: 'promotional', minimumParticipants: 10, maximumParticipants: 100 },
    { name: 'Supreme Monthly League', description: 'A monthly competition included in qualifying subscriptions.', competitionType: 'monthly', cadence: 'monthly', startGameweek: 12, endGameweek: 15, entryFeeCents: 500, displayedPrizeCents: 3000, projectedPrizeCents: 3000, guaranteedPrize: false, prizeType: 'projected', minimumParticipants: 20, maximumParticipants: 200 },
    { name: 'Supreme Half-Season', description: 'Long-form competition for sustained fantasy-management performance.', competitionType: 'half-season', cadence: 'half-season', startGameweek: 1, endGameweek: 19, currentGameweek: 12, entryFeeCents: 2000, displayedPrizeCents: 10000, projectedPrizeCents: 10000, guaranteedPrize: false, prizeType: 'minimum-participation', minimumParticipants: 20, maximumParticipants: 500, status: 'live' },
    { name: 'Supreme Season Cup', description: 'Full-season standings with result review before settlement.', competitionType: 'season', cadence: 'season', startGameweek: 1, endGameweek: 38, currentGameweek: 12, entryFeeCents: 4000, displayedPrizeCents: 30000, projectedPrizeCents: 30000, guaranteedPrize: false, prizeType: 'projected', minimumParticipants: 30, maximumParticipants: 1000, status: 'live' },
  ];
  await League.insertMany(seed.map((item) => ({
    ...item,
    officialSupremeLeague: true,
    customLeague: false,
    status: item.status || 'open',
    rules: ['Fantasy-management performance determines ranking.', 'Entries close at the published deadline.', 'Ties use the published tie-break rule.', 'Results are settled only after server-side review.'],
  })));
}

// -----------------------------------------------------------------------------
// Referral, league-access and Supreme competition system
// Integrated directly in this file. No separate growth integration module is used.
// -----------------------------------------------------------------------------
const localGrowth = (() => {
  const inlineModule = { exports: {} };
  const inlineExports = inlineModule.exports;
  (function loadIntegratedGrowthModule(module, exports, require) {
    'use strict';
    
    /**
     * Referral, league-access and Supreme-league automation module.
     *
     * Install from server.local.js after your Mongoose models and auth middleware
     * have been created. See LOCAL_GROWTH_INSTALL.md for the exact insertion points.
     */
    
    const crypto = require('crypto');
    
    const BRAND = {
      black: '#000000',
      pink: '#CB2957',
      grey: '#DDDDDD',
      lightGrey: '#EEEEEE',
      white: '#FFFFFF',
      green: '#18794E',
      red: '#B42318',
    };
    
    const cents = (value, fallback = 0) => {
      const parsed = Number.parseInt(value, 10);
      return Number.isFinite(parsed) ? parsed : fallback;
    };
    
    const bool = (value, fallback = false) => {
      if (value === undefined || value === null || value === '') return fallback;
      return ['true', '1', 'yes', 'on'].includes(String(value).toLowerCase());
    };
    
    const asDate = (value) => {
      const date = value ? new Date(value) : null;
      return date && !Number.isNaN(date.getTime()) ? date : null;
    };
    
    const normaliseEmail = (value) => String(value || '').trim().toLowerCase();
    const normaliseCode = (value) => String(value || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    
    const money = (amountCents, currency = 'USD') =>
      new Intl.NumberFormat('en-GB', {
        style: 'currency',
        currency,
        minimumFractionDigits: 2,
      }).format((Number(amountCents || 0) / 100));
    
    function createReferralCode() {
      return `SFL${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    }
    
    function createReference(prefix) {
      return `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    }
    
    function htmlEscape(value) {
      return String(value == null ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }
    
    function renderEmail({ preheader, title, message, buttonLabel, buttonUrl, details = [], tone = 'brand' }) {
      const accent = tone === 'success' ? BRAND.green : tone === 'danger' ? BRAND.red : BRAND.pink;
      const rows = details
        .filter((item) => item && item.label && item.value !== undefined)
        .map((item) => `
          <tr>
            <td style="padding:10px 12px;color:#666;font-size:13px;border-bottom:1px solid #eee;">${htmlEscape(item.label)}</td>
            <td style="padding:10px 12px;color:#111;font-size:13px;font-weight:700;text-align:right;border-bottom:1px solid #eee;">${htmlEscape(item.value)}</td>
          </tr>`)
        .join('');
    
      return `<!doctype html>
    <html>
    <head><meta name="viewport" content="width=device-width,initial-scale=1"><meta charset="utf-8"></head>
    <body style="margin:0;background:${BRAND.lightGrey};font-family:Arial,Helvetica,sans-serif;color:#111;">
      <div style="display:none;max-height:0;overflow:hidden;opacity:0;">${htmlEscape(preheader || title)}</div>
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:${BRAND.lightGrey};padding:28px 12px;">
        <tr><td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:620px;background:#fff;border-radius:18px;overflow:hidden;box-shadow:0 12px 32px rgba(0,0,0,.10);">
            <tr><td style="background:#000;padding:24px 30px;border-bottom:4px solid ${BRAND.pink};">
              <div style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#ddd;">Supreme Fantasy League</div>
              <div style="margin-top:6px;font-size:22px;font-weight:800;color:#fff;">Play smart. Win transparently.</div>
            </td></tr>
            <tr><td style="padding:32px 30px;">
              <div style="display:inline-block;background:${accent}16;color:${accent};font-size:12px;font-weight:800;padding:7px 10px;border-radius:999px;text-transform:uppercase;letter-spacing:.5px;">Account update</div>
              <h1 style="font-size:27px;line-height:1.2;margin:18px 0 12px;color:#000;">${htmlEscape(title)}</h1>
              <div style="font-size:16px;line-height:1.65;color:#444;">${message}</div>
              ${rows ? `<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-top:22px;border:1px solid #eee;border-radius:12px;overflow:hidden;">${rows}</table>` : ''}
              ${buttonLabel && buttonUrl ? `<div style="margin-top:28px;"><a href="${htmlEscape(buttonUrl)}" style="display:inline-block;background:${BRAND.pink};color:#fff;text-decoration:none;font-weight:800;padding:14px 20px;border-radius:10px;">${htmlEscape(buttonLabel)}</a></div>` : ''}
              <p style="margin:28px 0 0;font-size:12px;line-height:1.55;color:#777;">Supreme Fantasy League will never ask for your password, OTP, wallet PIN or full card details by email.</p>
            </td></tr>
            <tr><td style="background:#000;padding:18px 30px;color:#aaa;font-size:11px;line-height:1.5;">This message was sent because an activity occurred on your Supreme Fantasy League account.</td></tr>
          </table>
        </td></tr>
      </table>
    </body>
    </html>`;
    }
    
    function installLocalGrowthSystem(options) {
      const {
        app,
        mongoose,
        models,
        middleware = {},
        helpers = {},
      } = options || {};
    
      if (!app || !mongoose || !models) {
        throw new Error('installLocalGrowthSystem requires app, mongoose and models.');
      }
    
      const {
        User,
        UserProfile,
        Wallet,
        Transaction,
        Subscription,
        League,
        LeagueEntry,
        SupportTicket,
      } = models;
    
      const { requireAuth, requireAdmin } = middleware;
      const success = helpers.success || ((res, data, status = 200) => res.status(status).json({ success: true, data }));
      const failure = helpers.failure || ((res, status, message, errors = []) => res.status(status).json({ success: false, message, errors }));
    
      if (![User, Wallet, Transaction, Subscription, League, LeagueEntry].every(Boolean)) {
        throw new Error('Local growth system is missing one or more required Mongoose models.');
      }
    
      const { Schema } = mongoose;
    
      const ReferralAccount = mongoose.models.ReferralAccount || mongoose.model('ReferralAccount', new Schema({
        userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true },
        code: { type: String, required: true, unique: true, uppercase: true, trim: true, index: true },
        referredByUserId: { type: Schema.Types.ObjectId, ref: 'User', default: null, index: true },
        codeUsed: { type: String, default: '', uppercase: true, trim: true },
        signupNoticeSentAt: { type: Date, default: null },
        qualifiedAt: { type: Date, default: null },
        qualifyingTransactionId: { type: Schema.Types.ObjectId, ref: 'Transaction', default: null },
        rewardedAt: { type: Date, default: null },
        rewardTransactionId: { type: Schema.Types.ObjectId, ref: 'Transaction', default: null },
        rewardCents: { type: Number, default: 0, min: 0 },
      }, { timestamps: true }));
    
      const LeagueAccessPolicy = mongoose.models.LeagueAccessPolicy || mongoose.model('LeagueAccessPolicy', new Schema({
        leagueId: { type: Schema.Types.ObjectId, ref: 'League', required: true, unique: true, index: true },
        visibility: { type: String, enum: ['public', 'private'], default: 'private', index: true },
        inviteCode: { type: String, uppercase: true, trim: true, index: true },
        joinDeadlineAt: { type: Date, default: null, index: true },
        allowLateJoin: { type: Boolean, default: true },
        createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
      }, { timestamps: true }));
    
      LeagueAccessPolicy.schema.index({ inviteCode: 1 }, { unique: true, sparse: true });
    
      const SupremeLeagueMeta = mongoose.models.SupremeLeagueMeta || mongoose.model('SupremeLeagueMeta', new Schema({
        leagueId: { type: Schema.Types.ObjectId, ref: 'League', required: true, unique: true, index: true },
        cycleKey: { type: String, required: true, unique: true, index: true },
        cadence: { type: String, enum: ['weekly', 'bi-weekly', 'monthly', 'half-season', 'season', 'clash-captains'], required: true, index: true },
        scoringMode: { type: String, enum: ['manager-points', 'captain-vice'], default: 'manager-points', index: true },
        entryMode: { type: String, enum: ['subscription', 'weekly-flex', 'free-all'], default: 'subscription', index: true },
        periodLabel: { type: String, required: true },
        startGameweek: { type: Number, required: true },
        endGameweek: { type: Number, required: true },
        joinDeadlineAt: { type: Date, required: true },
        lastFixtureKickoffAt: { type: Date, default: null },
        finishedAt: { type: Date, default: null },
        dataCheckedAt: { type: Date, default: null },
        prizeCents: { type: Number, required: true, min: 0 },
        entryFeeCents: { type: Number, default: 0, min: 0 },
        settlementStatus: { type: String, enum: ['open', 'scoring', 'settled', 'failed'], default: 'open', index: true },
        settlementLockId: { type: String, default: '' },
        settlementLockedAt: { type: Date, default: null, index: true },
        settledAt: { type: Date, default: null },
        winnerUserIds: [{ type: Schema.Types.ObjectId, ref: 'User' }],
        splitAmountCents: { type: Number, default: 0 },
        lastMaintenanceAt: { type: Date, default: null },
        lastSettlementAttemptAt: { type: Date, default: null },
        manualSettlementAt: { type: Date, default: null },
        manualSettlementBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
        manualSettlementReason: { type: String, default: '' },
        lastError: { type: String, default: '' },
      }, { timestamps: true }));
    
      const GrowthEmailNotification = mongoose.models.GrowthEmailNotification || mongoose.model('GrowthEmailNotification', new Schema({
        eventKey: { type: String, required: true, unique: true, index: true },
        userId: { type: Schema.Types.ObjectId, ref: 'User', default: null, index: true },
        recipientEmail: { type: String, required: true, lowercase: true, trim: true },
        category: { type: String, required: true, index: true },
        subject: { type: String, required: true },
        status: { type: String, enum: ['pending', 'sent', 'failed', 'skipped'], default: 'pending', index: true },
        attempts: { type: Number, default: 0 },
        resendEmailId: { type: String, default: '' },
        errorMessage: { type: String, default: '' },
        sentAt: { type: Date, default: null },
        metadata: { type: Schema.Types.Mixed, default: {} },
      }, { timestamps: true }));
    
      const referralRewardCents = cents(process.env.REFERRAL_REWARD_CENTS, 100);
      const referralTypes = new Set(
        String(process.env.REFERRAL_QUALIFYING_TRANSACTION_TYPES || 'subscription,entry-fee')
          .split(',')
          .map((item) => item.trim())
          .filter(Boolean)
      );
      const appUrl = String(process.env.CLIENT_APP_URL || process.env.CLIENT_ORIGIN || 'http://localhost:3000').replace(/\/$/, '');
      const fplBaseUrl = String(process.env.FPL_BASE_URL || 'https://fantasy.premierleague.com/api').replace(/\/$/, '');
      const maintenanceIntervalMs = cents(process.env.LOCAL_GROWTH_MAINTENANCE_INTERVAL_MS, 300000);
      const emailsEnabled = bool(process.env.EMAILS_ENABLED, true);
    
      async function sendEmail({ eventKey, userId, to, category, subject, preheader, title, message, buttonLabel, buttonUrl, details, tone, metadata = {} }) {
        const recipientEmail = normaliseEmail(to);
        if (!recipientEmail) return { skipped: true, reason: 'missing-recipient' };
    
        const existing = await GrowthEmailNotification.findOne({ eventKey }).lean();
        if (existing && ['sent', 'skipped'].includes(existing.status)) {
          return { skipped: true, reason: 'duplicate', id: existing.resendEmailId || '' };
        }
    
        const record = await GrowthEmailNotification.findOneAndUpdate(
          { eventKey },
          {
            $setOnInsert: { userId: userId || null, recipientEmail, category, subject, metadata },
            $set: { status: 'pending', errorMessage: '' },
            $inc: { attempts: 1 },
          },
          { upsert: true, new: true }
        );
    
        if (!emailsEnabled) {
          record.status = 'skipped';
          record.errorMessage = 'EMAILS_ENABLED is false.';
          await record.save();
          return { skipped: true, reason: 'disabled' };
        }
    
        const apiKey = String(process.env.RESENDER_API_KEY || '').trim();
        const from = String(process.env.SENDING_EMAIL || '').trim();
        if (!apiKey || !from) {
          record.status = 'failed';
          record.errorMessage = 'RESENDER_API_KEY or SENDING_EMAIL is missing.';
          await record.save();
          return { skipped: false, error: record.errorMessage };
        }
    
        try {
          const response = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${apiKey}`,
              'Content-Type': 'application/json',
              'Idempotency-Key': eventKey.slice(0, 256),
            },
            body: JSON.stringify({
              from,
              to: [recipientEmail],
              subject,
              html: renderEmail({ preheader, title, message, buttonLabel, buttonUrl, details, tone }),
            }),
          });
          const payload = await response.json().catch(() => ({}));
          if (!response.ok) throw new Error(payload.message || `Resend returned HTTP ${response.status}.`);
          record.status = 'sent';
          record.resendEmailId = payload.id || '';
          record.sentAt = new Date();
          await record.save();
          return { skipped: false, id: payload.id || '' };
        } catch (error) {
          record.status = 'failed';
          record.errorMessage = String(error.message || error).slice(0, 1000);
          await record.save();
          console.error('Growth email failed:', record.errorMessage);
          return { skipped: false, error: record.errorMessage };
        }
      }
    
      function configuredDayList(name, fallback) {
        const raw = String(process.env[name] || fallback);
        return [...new Set(raw.split(',').map((value) => Number.parseInt(value.trim(), 10)).filter((value) => Number.isInteger(value) && value >= 1 && value <= 14))];
      }

      function utcDayStart(value = new Date()) {
        const date = new Date(value);
        return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
      }

      function calendarDaysBetween(later, earlier) {
        return Math.round((utcDayStart(later).getTime() - utcDayStart(earlier).getTime()) / 86400000);
      }

      async function userEmailNotificationsAllowed(userId, preferenceKey = '') {
        if (!UserProfile) return true;
        const profile = await UserProfile.findOne({ userId }).select('notificationPreferences').lean();
        const preferences = profile?.notificationPreferences || {};
        if (preferences.emailNotifications === false) return false;
        if (preferenceKey && preferences[preferenceKey] === false) return false;
        return true;
      }

      async function sendAccountSetupReminders(now = new Date()) {
        const afterHours = Math.max(1, Number(process.env.ACCOUNT_SETUP_REMINDER_AFTER_HOURS || 24));
        const repeatDays = Math.max(1, Number(process.env.ACCOUNT_SETUP_REMINDER_REPEAT_DAYS || 3));
        const cutoff = new Date(now.getTime() - afterHours * 3600000);
        const users = await User.find({
          role: 'user',
          status: 'active',
          createdAt: { $lte: cutoff },
          email: { $exists: true, $ne: '' },
        }).select('_id fullName email fplManagerId createdAt').lean();

        if (!users.length) return { checked: 0, sent: 0, skipped: 0 };

        const userIds = users.map((user) => user._id);
        const activeSubscriptions = await Subscription.find({
          userId: { $in: userIds },
          status: 'active',
          $or: [
            { validUntil: { $gt: now } },
            { validUntil: null, endDate: { $gt: now } },
            { validUntil: null, endDate: null, renewalDate: { $gt: now } },
          ],
        }).select('userId').lean();
        const subscribed = new Set(activeSubscriptions.map((item) => String(item.userId)));

        let sent = 0;
        let skipped = 0;
        for (const user of users) {
          const hasTeam = Boolean(String(user.fplManagerId || '').trim());
          const hasSubscription = subscribed.has(String(user._id));
          if (hasTeam && hasSubscription) continue;

          const ageHours = Math.max(0, (now.getTime() - new Date(user.createdAt).getTime()) / 3600000);
          if (ageHours < afterHours) continue;
          const reminderIndex = Math.floor(Math.max(0, ageHours - afterHours) / (repeatDays * 24));
          const eventKey = `account-setup:${user._id}:${reminderIndex}`;

          if (!(await userEmailNotificationsAllowed(user._id))) {
            skipped += 1;
            continue;
          }

          const steps = [];
          if (!hasTeam) {
            steps.push('<li><strong>Link your FPL team:</strong> open the Team page and paste your FPL entry link, for example <code>https://fantasy.premierleague.com/en/entry/1149514/transfers</code>. We extract your manager number automatically.</li>');
          }
          if (!hasSubscription) {
            steps.push('<li><strong>Choose your subscription:</strong> open Subscription and select the plan that matches the competitions you want to enter.</li>');
            steps.push('<li><strong>Pay:</strong> confirm your payment method, then complete the Paynow checkout or confirm the wallet payment if you have enough balance.</li>');
          }
          steps.push('<li><strong>Finish setup:</strong> once your team is linked and your subscription is active, the eligible Supreme leagues are handled automatically by the platform.</li>');

          const destination = !hasTeam ? `${appUrl}/app/team` : `${appUrl}/app/subscription`;
          const result = await sendEmail({
            eventKey,
            userId: user._id,
            to: user.email,
            category: 'account-setup',
            subject: 'ACTION REQUIRED!!!! Complete your Supreme Fantasy League setup',
            preheader: 'Link your FPL team and activate your subscription before the next competition deadline.',
            title: 'ACTION REQUIRED — finish setting up your account',
            tone: 'danger',
            message: `<p style="margin:0 0 14px;">Hi ${htmlEscape(user.fullName || 'there')}, your Supreme Fantasy League account is registered, but there are still steps required before you can participate fully.</p><ol style="margin:0;padding-left:22px;line-height:1.75;">${steps.join('')}</ol>`,
            buttonLabel: !hasTeam ? 'Link my FPL team' : 'Complete my subscription',
            buttonUrl: destination,
            details: [
              { label: 'FPL team linked', value: hasTeam ? 'Yes' : 'No' },
              { label: 'Active subscription', value: hasSubscription ? 'Yes' : 'No' },
            ],
            metadata: { hasTeam, hasSubscription, reminderIndex },
          });
          if (result?.skipped || result?.error) skipped += 1;
          else sent += 1;
        }
        return { checked: users.length, sent, skipped };
      }

      async function sendGameweekDeadlineReminders(now = new Date()) {
        if (FPL_DATA_MODE !== 'public') return { skipped: true, reason: 'fpl-data-mode-not-public', checked: 0, sent: 0 };
        const reminderDays = configuredDayList('GAMEWEEK_REMINDER_DAYS', '3,2');
        if (!reminderDays.length) return { skipped: true, reason: 'no-reminder-days-configured', checked: 0, sent: 0 };

        const bootstrap = await fetchFplBootstrap();
        const events = (Array.isArray(bootstrap?.events) ? bootstrap.events : [])
          .filter((event) => event?.deadline_time && !event.finished && new Date(event.deadline_time) > now)
          .sort((a, b) => new Date(a.deadline_time) - new Date(b.deadline_time));
        const nextEvent = events[0];
        if (!nextEvent) return { skipped: true, reason: 'no-upcoming-gameweek', checked: 0, sent: 0 };

        const deadline = new Date(nextEvent.deadline_time);
        const daysBefore = calendarDaysBetween(deadline, now);
        if (!reminderDays.includes(daysBefore)) return { skipped: true, reason: 'not-a-reminder-day', gameweek: Number(nextEvent.id), daysBefore, checked: 0, sent: 0 };

        const users = await User.find({ role: 'user', status: 'active', email: { $exists: true, $ne: '' } })
          .select('_id fullName email fplManagerId').lean();
        if (!users.length) return { checked: 0, sent: 0 };
        const userIds = users.map((user) => user._id);
        const subscriptions = await Subscription.find({
          userId: { $in: userIds },
          status: 'active',
          $or: [
            { validUntil: { $gt: now } },
            { validUntil: null, endDate: { $gt: now } },
            { validUntil: null, endDate: null, renewalDate: { $gt: now } },
          ],
        }).select('userId planName validUntil').lean();
        const subscriptionMap = new Map(subscriptions.map((item) => [String(item.userId), item]));

        const formattedDeadline = deadline.toLocaleString('en-GB', {
          weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short',
        });
        let sent = 0;
        let skipped = 0;
        for (const user of users) {
          const subscription = subscriptionMap.get(String(user._id));
          if (!subscription) continue;
          if (!(await userEmailNotificationsAllowed(user._id, 'deadlineReminders'))) {
            skipped += 1;
            continue;
          }
          const eventKey = `gameweek-deadline:${nextEvent.id}:${daysBefore}:${user._id}`;
          const hasTeam = Boolean(String(user.fplManagerId || '').trim());
          const result = await sendEmail({
            eventKey,
            userId: user._id,
            to: user.email,
            category: 'gameweek-reminder',
            subject: `ACTION REQUIRED!!!! Gameweek ${nextEvent.id} deadline is ${daysBefore} day${daysBefore === 1 ? '' : 's'} away`,
            preheader: `Your Gameweek ${nextEvent.id} deadline is approaching. Make sure your FPL team is ready.`,
            title: `ACTION REQUIRED — Gameweek ${nextEvent.id} is ${daysBefore} day${daysBefore === 1 ? '' : 's'} away`,
            tone: 'danger',
            message: `<p style="margin:0 0 14px;">Hi ${htmlEscape(user.fullName || 'there')}, the next FPL gameweek deadline is approaching. Please make your final team decisions before the deadline.</p><p style="margin:0;">${hasTeam ? 'Your FPL manager is linked. Review your starting XI, captain and transfers before the deadline.' : 'You have not linked an FPL manager yet. Link it now so your Supreme Fantasy League participation can be processed correctly.'}</p>`,
            buttonLabel: hasTeam ? 'Review my team' : 'Link my FPL team',
            buttonUrl: hasTeam ? `${appUrl}/app/team` : `${appUrl}/app/team`,
            details: [
              { label: 'Gameweek', value: nextEvent.id },
              { label: 'Deadline', value: formattedDeadline },
              { label: 'Subscription', value: subscription.planName || 'Active subscription' },
            ],
            metadata: { gameweek: Number(nextEvent.id), deadline: deadline.toISOString(), daysBefore },
          });
          if (result?.skipped || result?.error) skipped += 1;
          else sent += 1;
        }
        return { skipped: false, gameweek: Number(nextEvent.id), deadline: deadline.toISOString(), daysBefore, checked: users.length, sent, skipped };
      }

      async function sendSubscriptionLapseReminders(now = new Date()) {
        const reminderDays = configuredDayList('SUBSCRIPTION_LAPSE_REMINDER_DAYS', '3,1');
        if (!reminderDays.length) return { skipped: true, reason: 'no-lapse-days-configured', checked: 0, sent: 0 };
        const maxDays = Math.max(...reminderDays);
        const upper = new Date(now.getTime() + maxDays * 86400000 + 86400000);
        const subscriptions = await Subscription.find({
          status: 'active',
          validUntil: { $gt: now, $lte: upper },
        }).select('_id userId planName validUntil').lean();
        if (!subscriptions.length) return { checked: 0, sent: 0 };

        const users = await User.find({
          _id: { $in: subscriptions.map((item) => item.userId) },
          role: 'user',
          status: 'active',
          email: { $exists: true, $ne: '' },
        }).select('_id fullName email').lean();
        const userMap = new Map(users.map((user) => [String(user._id), user]));
        let sent = 0;
        let skipped = 0;
        for (const subscription of subscriptions) {
          const user = userMap.get(String(subscription.userId));
          if (!user) continue;
          const daysLeft = Math.max(0, Math.ceil((new Date(subscription.validUntil).getTime() - now.getTime()) / 86400000));
          if (!reminderDays.includes(daysLeft)) continue;
          if (!(await userEmailNotificationsAllowed(user._id, 'deadlineReminders'))) {
            skipped += 1;
            continue;
          }
          const eventKey = `subscription-lapse:${subscription._id}:${daysLeft}`;
          const validUntil = new Date(subscription.validUntil);
          const result = await sendEmail({
            eventKey,
            userId: user._id,
            to: user.email,
            category: 'subscription-lapse',
            subject: `ACTION REQUIRED!!!! Your ${subscription.planName || 'Supreme Fantasy League'} subscription expires in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`,
            preheader: 'Renew before your subscription expires so you do not lose access to eligible competitions.',
            title: `ACTION REQUIRED — your subscription is about to lapse`,
            tone: 'danger',
            message: `<p style="margin:0 0 14px;">Hi ${htmlEscape(user.fullName || 'there')}, your ${htmlEscape(subscription.planName || 'Supreme Fantasy League')} subscription is approaching its expiry point.</p><p style="margin:0;">Renew before it expires to keep your eligible competition access. Expired subscriptions are not used for future automatic league entries.</p>`,
            buttonLabel: 'Renew my subscription',
            buttonUrl: `${appUrl}/app/subscription`,
            details: [
              { label: 'Plan', value: subscription.planName || 'Subscription' },
              { label: 'Expires', value: validUntil.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC' },
              { label: 'Time remaining', value: `${daysLeft} day${daysLeft === 1 ? '' : 's'}` },
            ],
            metadata: { subscriptionId: String(subscription._id), validUntil: validUntil.toISOString(), daysLeft },
          });
          if (result?.skipped || result?.error) skipped += 1;
          else sent += 1;
        }
        return { checked: subscriptions.length, sent, skipped };
      }

      async function sendLeagueJoinDeadlineReminders(now = new Date()) {
        if (FPL_DATA_MODE !== 'public') return { skipped: true, reason: 'fpl-data-mode-not-public', checked: 0, sent: 0 };
        const upper = new Date(now.getTime() + 48 * 60 * 60 * 1000);
        const metas = await SupremeLeagueMeta.find({
          settlementStatus: 'open',
          joinDeadlineAt: { $gt: now, $lte: upper },
        }).sort({ joinDeadlineAt: 1 }).lean();
        if (!metas.length) return { checked: 0, sent: 0, deadlines: 0 };

        const leagueIds = metas.map((meta) => meta.leagueId);
        const [leagues, entries, users] = await Promise.all([
          League.find({ _id: { $in: leagueIds } }).select('_id name status entryFeeCents').lean(),
          LeagueEntry.find({ leagueId: { $in: leagueIds }, paymentStatus: { $in: ['paid', 'completed'] } }).select('leagueId userId').lean(),
          User.find({ role: 'user', status: 'active', email: { $exists: true, $ne: '' } }).select('_id fullName email fplManagerId').lean(),
        ]);
        const leagueMap = new Map(leagues.map((league) => [String(league._id), league]));
        const joined = new Set(entries.map((entry) => `${entry.userId}:${entry.leagueId}`));
        const subscriptions = await activeSubscriptionsForUsers(users.map((user) => user._id), now);
        const subscriptionsByUser = new Map();
        for (const sub of subscriptions) {
          const key = String(sub.userId);
          if (!subscriptionsByUser.has(key)) subscriptionsByUser.set(key, []);
          subscriptionsByUser.get(key).push(sub);
        }

        const deadlineGroups = new Map();
        for (const meta of metas) {
          const key = new Date(meta.joinDeadlineAt).toISOString();
          if (!deadlineGroups.has(key)) deadlineGroups.set(key, []);
          deadlineGroups.get(key).push(meta);
        }

        let checked = 0;
        let sent = 0;
        let skipped = 0;
        for (const [deadlineIso, group] of deadlineGroups) {
          const deadline = new Date(deadlineIso);
          const hoursLeft = Math.max(0, (deadline.getTime() - now.getTime()) / 3600000);
          const reminderBucket = hoursLeft <= 24 ? 24 : 48;
          const formattedDeadline = deadline.toLocaleString('en-GB', {
            weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short',
          });

          for (const user of users) {
            checked += 1;
            if (!(await userEmailNotificationsAllowed(user._id, 'deadlineReminders'))) {
              skipped += 1;
              continue;
            }
            const subs = subscriptionsByUser.get(String(user._id)) || [];
            const eligible = group.filter((meta) => {
              if (joined.has(`${user._id}:${meta.leagueId}`)) return false;
              if (meta.entryMode === 'free-all') return Boolean(String(user.fplManagerId || '').trim());
              if (meta.entryMode === 'weekly-flex') return true;
              return subs.some((sub) => subscriptionEntitles(sub, meta.cadence, meta));
            });
            if (!eligible.length) continue;

            const rows = eligible.map((meta) => {
              const league = leagueMap.get(String(meta.leagueId));
              const access = meta.entryMode === 'weekly-flex'
                ? `${money(Number(league?.entryFeeCents ?? meta.entryFeeCents ?? 100))} one-off or eligible subscription`
                : meta.entryMode === 'free-all' ? 'Free entry' : 'Included with eligible subscription';
              return { label: league?.name || meta.periodLabel, value: access };
            });
            rows.push({ label: 'Entry deadline', value: formattedDeadline });

            const upcomingClash = eligible.some((meta) => meta.cadence === 'clash-captains') || group.some((meta) => meta.cadence === 'clash-captains');
            const result = await sendEmail({
              eventKey: `league-join-deadline:${deadlineIso}:${reminderBucket}:${user._id}`,
              userId: user._id,
              to: user.email,
              category: 'league-reminder',
              subject: `${reminderBucket} hours or less to enter your upcoming Supreme competitions`,
              preheader: `Entries close at the official FPL deadline. Your eligible competitions are ready now.`,
              title: `${reminderBucket} hours or less before entries close`,
              tone: reminderBucket === 24 ? 'danger' : 'brand',
              message: `<p style="margin:0 0 14px;">Hi ${htmlEscape(user.fullName || 'there')}, your eligible Supreme competitions are already open. Join before the official FPL deadline below.</p><p style="margin:0 0 14px;">The weekly league can be entered with an eligible subscription or as a ${money(cents(process.env.SUPREME_WEEKLY_ENTRY_FEE_CENTS, 100))} one-off entry for a ${money(cents(process.env.SUPREME_WEEKLY_PRIZE_CENTS, 1000))} guaranteed prize.</p>${upcomingClash ? `<p style="margin:0;"><strong>September special:</strong> Clash of the Captains is free for linked users. Your captain's raw FPL points plus your vice-captain's raw FPL points determine the leaderboard, with ${money(cents(process.env.SUPREME_CLASH_CAPTAINS_PRIZE_CENTS, 300))} for first place.</p>` : ''}`,
              buttonLabel: 'View open competitions',
              buttonUrl: `${appUrl}/app/leagues/supreme`,
              details: rows.slice(0, 8),
              metadata: { deadline: deadlineIso, reminderBucket, leagueIds: eligible.map((meta) => String(meta.leagueId)), clashPromoted: upcomingClash },
            });
            if (result?.skipped || result?.error) skipped += 1; else sent += 1;
          }
        }
        return { checked, sent, skipped, deadlines: deadlineGroups.size };
      }

      async function sendScheduledUserEmails(now = new Date()) {
        const result = {
          accountSetup: { checked: 0, sent: 0, skipped: 0 },
          leagueDeadlines: { checked: 0, sent: 0, skipped: 0 },
          gameweek: { checked: 0, sent: 0, skipped: 0 },
          subscriptionLapse: { checked: 0, sent: 0, skipped: 0 },
        };
        result.accountSetup = await sendAccountSetupReminders(now);
        result.leagueDeadlines = await sendLeagueJoinDeadlineReminders(now);
        result.gameweek = await sendGameweekDeadlineReminders(now);
        result.subscriptionLapse = await sendSubscriptionLapseReminders(now);
        return result;
      }

      async function uniqueReferralCode() {
        for (let attempt = 0; attempt < 12; attempt += 1) {
          const code = createReferralCode();
          const exists = await ReferralAccount.exists({ code });
          if (!exists) return code;
        }
        throw new Error('Could not generate a unique referral code.');
      }
    
      async function ensureReferralAccount(user, suppliedCode = '') {
        if (!user || !user._id) throw new Error('A saved user is required.');
        const existing = await ReferralAccount.findOne({ userId: user._id });
        if (existing) return existing;
    
        const codeUsed = normaliseCode(suppliedCode);
        let referrer = null;
        if (codeUsed) {
          referrer = await ReferralAccount.findOne({ code: codeUsed });
          if (referrer && String(referrer.userId) === String(user._id)) referrer = null;
        }
    
        const account = await ReferralAccount.create({
          userId: user._id,
          code: await uniqueReferralCode(),
          referredByUserId: referrer ? referrer.userId : null,
          codeUsed: referrer ? codeUsed : '',
        });
    
        if (referrer) {
          const referrerUser = await User.findById(referrer.userId).lean();
          if (referrerUser?.email) {
            await sendEmail({
              eventKey: `referral-signup:${account._id}`,
              userId: referrerUser._id,
              to: referrerUser.email,
              category: 'referral-signup',
              subject: 'Your referral just joined Supreme',
              preheader: 'Your referral code has been used.',
              title: 'Your referral network is growing',
              message: `<p style="margin:0;">A new Supreme Fantasy League member signed up using your referral code <strong>${htmlEscape(referrer.code)}</strong>.</p><p>When their first eligible purchase is completed, your referral reward will be credited automatically.</p>`,
              buttonLabel: 'View my referral activity',
              buttonUrl: `${appUrl}/app/profile`,
              details: [{ label: 'Referral code', value: referrer.code }],
            });
            account.signupNoticeSentAt = new Date();
            await account.save();
          }
        }
    
        return account;
      }
    
      async function backfillReferralAccounts(limit = 500) {
        const users = await User.find({}).select('_id email').limit(limit).lean();
        for (const user of users) {
          await ensureReferralAccount(user).catch((error) => console.error('Referral backfill failed:', error.message));
        }
      }
    
      async function getReferralSummary(userId) {
        const account = await ReferralAccount.findOne({ userId }).lean();
        if (!account) return null;
        const [signedUpCount, qualifiedCount, rewarded] = await Promise.all([
          ReferralAccount.countDocuments({ referredByUserId: userId }),
          ReferralAccount.countDocuments({ referredByUserId: userId, qualifiedAt: { $ne: null } }),
          ReferralAccount.aggregate([
            { $match: { referredByUserId: new mongoose.Types.ObjectId(userId), rewardedAt: { $ne: null } } },
            { $group: { _id: null, total: { $sum: '$rewardCents' } } },
          ]),
        ]);
        return {
          code: account.code,
          shareUrl: `${appUrl}/register?ref=${encodeURIComponent(account.code)}`,
          signedUpCount,
          qualifiedCount,
          rewardCents: rewarded[0]?.total || 0,
          rewardPerQualifiedReferralCents: referralRewardCents,
          currency: 'USD',
        };
      }
    
      function walletBalanceField() {
        if (Wallet.schema.path('availableBalanceCents')) return 'availableBalanceCents';
        if (Wallet.schema.path('balanceCents')) return 'balanceCents';
        throw new Error('Wallet model has no supported balance field.');
      }
    
      async function creditWallet({ userId, amountCents, reference, reason, functionName }) {
        const balanceField = walletBalanceField();
        const duplicate = await Transaction.exists({ reference });
        if (duplicate) return Transaction.findOne({ reference });
    
        const tx = await Transaction.create({
          userId,
          reference,
          type: 'adjustment',
          direction: 'credit',
          amountCents,
          currency: 'USD',
          provider: 'supreme',
          providerReference: reference,
          status: 'completed',
          description: reason,
          metadata: { purpose: 'referral-reward', functionName },
        });
    
        await Wallet.updateOne(
          { userId },
          {
            $inc: { [balanceField]: amountCents },
            $set: {
              updatedAt: new Date(),
              lastBalanceUpdateAt: new Date(),
              lastBalanceUpdateReason: reason,
              lastBalanceUpdateFunction: functionName,
            },
          },
          { upsert: true }
        );
        return tx;
      }
    
      async function processReferralRewards() {
        if (referralRewardCents <= 0) return { rewarded: 0 };
        const pending = await ReferralAccount.find({ referredByUserId: { $ne: null }, rewardedAt: null }).limit(200);
        let rewarded = 0;
    
        for (const referral of pending) {
          const qualifyingTransaction = await Transaction.findOne({
            userId: referral.userId,
            status: 'completed',
            type: { $in: Array.from(referralTypes) },
            direction: { $in: ['debit', 'credit'] },
          }).sort({ createdAt: 1 });
          if (!qualifyingTransaction) continue;
    
          const rewardReference = `REF-${referral._id}`;
          const rewardTx = await creditWallet({
            userId: referral.referredByUserId,
            amountCents: referralRewardCents,
            reference: rewardReference,
            reason: 'Referral reward for a qualified new member',
            functionName: 'processReferralRewards',
          });
    
          referral.qualifiedAt = referral.qualifiedAt || qualifyingTransaction.createdAt || new Date();
          referral.qualifyingTransactionId = qualifyingTransaction._id;
          referral.rewardedAt = new Date();
          referral.rewardTransactionId = rewardTx._id;
          referral.rewardCents = referralRewardCents;
          await referral.save();
          rewarded += 1;
    
          const referrerUser = await User.findById(referral.referredByUserId).lean();
          if (referrerUser?.email) {
            await sendEmail({
              eventKey: `referral-reward:${referral._id}`,
              userId: referrerUser._id,
              to: referrerUser.email,
              category: 'referral-reward',
              subject: `${money(referralRewardCents)} referral reward added to your wallet`,
              preheader: 'A referral reward has been credited to your wallet.',
              title: 'Referral reward credited',
              tone: 'success',
              message: '<p style="margin:0;">A member you referred completed their first eligible purchase. Your reward has been added to your Supreme wallet.</p>',
              buttonLabel: 'Open my wallet',
              buttonUrl: `${appUrl}/app/wallet`,
              details: [
                { label: 'Reward', value: money(referralRewardCents) },
                { label: 'Reference', value: rewardReference },
              ],
            });
          }
        }
        return { rewarded };
      }
    
      async function setLeagueAccessPolicy({ league, creatorUserId, visibility, inviteCode, joinDeadlineAt, allowLateJoin }) {
        const code = normaliseCode(inviteCode) || normaliseCode(league.inviteCode) || `LG${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
        const deadline = asDate(joinDeadlineAt);
        if (!deadline) throw new Error('A valid league joining deadline is required.');
        if (deadline <= new Date()) throw new Error('The league joining deadline must be in the future.');

        let fplDeadline = asDate(league.fplJoinDeadlineAt);
        if (!fplDeadline && FPL_DATA_MODE === 'public' && Number(league.startGameweek) > 0) {
          try {
            const schedule = await getFplGameweekSchedule(league.startGameweek, { includeFixtures: false });
            fplDeadline = schedule.deadlineAt;
          } catch (error) {
            console.warn(`Could not verify FPL joining deadline for league ${league._id}:`, error.message);
          }
        }
        if (fplDeadline && deadline > fplDeadline) {
          const error = new Error(`The league joining deadline cannot be later than the official FPL deadline (${fplDeadline.toISOString()}).`);
          error.status = 409;
          throw error;
        }
    
        return LeagueAccessPolicy.findOneAndUpdate(
          { leagueId: league._id },
          {
            $set: {
              visibility: visibility === 'public' ? 'public' : 'private',
              inviteCode: code,
              joinDeadlineAt: deadline,
              allowLateJoin: allowLateJoin !== false,
              createdBy: creatorUserId,
            },
          },
          { upsert: true, new: true, runValidators: true }
        );
      }
    
      async function getLeagueAccessPolicy(leagueId) {
        return LeagueAccessPolicy.findOne({ leagueId }).lean();
      }
    
      async function assertLeagueJoinAllowed({ league, userId, inviteCode = '' }) {
        const policy = await LeagueAccessPolicy.findOne({ leagueId: league._id }).lean();
        if (!policy) return { policy: null, lateJoinWarning: false };
        if (policy.joinDeadlineAt && new Date(policy.joinDeadlineAt) <= new Date()) {
          const error = new Error('The joining deadline for this league has passed.');
          error.status = 409;
          throw error;
        }
        if (policy.visibility === 'private' && normaliseCode(inviteCode) !== policy.inviteCode) {
          const error = new Error('A valid invitation code is required for this private league.');
          error.status = 403;
          throw error;
        }
        let currentGameweek = Number(league.currentGameweek || 0);
        try {
          const state = await fantasyProvider.getGameState();
          currentGameweek = Number(state.currentGameweek || currentGameweek || 0);
        } catch {
          // Fall back to the league's last known gameweek when the provider is unavailable.
        }
        const gameStarted = currentGameweek >= Number(league.startGameweek || 0) && Number(league.startGameweek || 0) > 0;
        if (gameStarted && policy.allowLateJoin === false) {
          const error = new Error('This league has already started and late joining is disabled.');
          error.status = 409;
          throw error;
        }
        return {
          policy,
          lateJoinWarning: Boolean(gameStarted && policy.allowLateJoin !== false),
          warningMessage: gameStarted && policy.allowLateJoin !== false
            ? 'This league has already started. You may still join before the deadline, but your chances of winning may be slim because other members can already be far ahead.'
            : '',
        };
      }
    
      async function notifySupportTicketReceived({ ticket, user }) {
        if (!ticket || !user?.email) return;
        const ticketReference = ticket.reference || ticket.ticketNumber || String(ticket._id);
        await sendEmail({
          eventKey: `support-received:${ticket._id}`,
          userId: user._id,
          to: user.email,
          category: 'support-ticket',
          subject: `We’re on it — support request ${ticketReference}`,
          preheader: 'Your support ticket is now in our queue.',
          title: 'Your support request has been received',
          message: `<p style="margin:0;">Thank you for contacting Supreme Fantasy League. Your request is in our support queue and will be attended to shortly.</p><p>Please keep the reference below for follow-up.</p>`,
          buttonLabel: 'Open support',
          buttonUrl: `${appUrl}/app/support`,
          details: [
            { label: 'Ticket reference', value: ticketReference },
            { label: 'Status', value: ticket.status || 'open' },
            { label: 'Category', value: ticket.category || 'general' },
          ],
        });
      }
    
      async function fetchFplBootstrap() {
        const response = await fetch(`${fplBaseUrl}/bootstrap-static/`, { headers: { Accept: 'application/json' } });
        if (!response.ok) throw new Error(`FPL bootstrap request failed with HTTP ${response.status}.`);
        return response.json();
      }
    
      function seasonKey(events) {
        const first = events[0] && new Date(events[0].deadline_time);
        const last = events[events.length - 1] && new Date(events[events.length - 1].deadline_time);
        if (!first || !last) return String(new Date().getUTCFullYear());
        return `${first.getUTCFullYear()}-${String(last.getUTCFullYear()).slice(-2)}`;
      }
    
      function supremeDefinitions(bootstrap) {
        const events = Array.isArray(bootstrap?.events) ? bootstrap.events : [];
        if (!events.length) return [];

        const now = new Date();
        const horizon = new Date(now.getTime() + SUPREME_PLANNING_HORIZON_DAYS * 86400000);
        const season = seasonKey(events);
        const eventById = new Map(events.map((event) => [Number(event.id), event]));
        const definitions = new Map();
        const isFutureJoinableEvent = (event) => {
          if (!event?.deadline_time) return false;
          const deadline = new Date(event.deadline_time);
          return !Number.isNaN(deadline.getTime()) && deadline > now && deadline <= horizon;
        };
        const add = ({ cadence, keySuffix, label, startGameweek, endGameweek, prizeCents, entryFeeCents = 0, scoringMode = 'manager-points', entryMode = 'subscription' }) => {
          const first = eventById.get(Number(startGameweek));
          const last = eventById.get(Number(endGameweek));
          if (!first?.deadline_time || !last) return;
          const joinDeadlineAt = new Date(first.deadline_time);
          if (Number.isNaN(joinDeadlineAt.getTime()) || joinDeadlineAt <= now || joinDeadlineAt > horizon) return;
          const cycleKey = `${season}:${cadence}:${keySuffix}`;
          definitions.set(cycleKey, {
            cadence,
            cycleKey,
            periodLabel: label,
            startGameweek: Number(startGameweek),
            endGameweek: Number(endGameweek),
            joinDeadlineAt,
            prizeCents,
            entryFeeCents,
            scoringMode,
            entryMode,
          });
        };

        const planningEvents = events.filter(isFutureJoinableEvent).sort((a, b) => Number(a.id) - Number(b.id));
        for (const event of planningEvents) {
          const gw = Number(event.id);
          add({
            cadence: 'weekly', keySuffix: `gw${gw}`, label: `Gameweek ${gw}`, startGameweek: gw, endGameweek: gw,
            prizeCents: cents(process.env.SUPREME_WEEKLY_PRIZE_CENTS, 1000),
            entryFeeCents: cents(process.env.SUPREME_WEEKLY_ENTRY_FEE_CENTS, 100),
            entryMode: 'weekly-flex',
          });
        }

        // Bi-weekly competitions are built from the real FPL gameweek sequence. The
        // first FPL deadline is always the entry deadline; no calendar arithmetic is used.
        for (let gw = 1; gw <= 38; gw += 2) {
          const first = eventById.get(gw);
          const second = eventById.get(Math.min(gw + 1, 38));
          if (!first || !second || !isFutureJoinableEvent(first)) continue;
          add({
            cadence: 'bi-weekly', keySuffix: `gw${gw}-${Math.min(gw + 1, 38)}`,
            label: `Gameweeks ${gw}-${Math.min(gw + 1, 38)}`,
            startGameweek: gw, endGameweek: Math.min(gw + 1, 38),
            prizeCents: cents(process.env.SUPREME_BIWEEKLY_PRIZE_CENTS, 1500),
          });
        }

        // FPL itself publishes named monthly phases (for example September). Use
        // those phase boundaries instead of guessing where a month starts/ends.
        const phases = Array.isArray(bootstrap?.phases) ? bootstrap.phases : [];
        for (const phase of phases) {
          const phaseName = String(phase?.name || '').trim();
          const startGameweek = Number(phase?.start_event || 0);
          const endGameweek = Number(phase?.stop_event || 0);
          if (!phaseName || !startGameweek || !endGameweek || /overall/i.test(phaseName)) continue;
          const startEvent = eventById.get(startGameweek);
          if (!startEvent || !isFutureJoinableEvent(startEvent)) continue;
          const startDeadline = new Date(startEvent.deadline_time);
          const cycleSuffix = `${startDeadline.getUTCFullYear()}-${String(startDeadline.getUTCMonth() + 1).padStart(2, '0')}`;
          add({
            cadence: 'monthly', keySuffix: cycleSuffix,
            label: `${phaseName} ${startDeadline.getUTCFullYear()}`,
            startGameweek, endGameweek,
            prizeCents: cents(process.env.SUPREME_MONTHLY_PRIZE_CENTS, 3000),
          });
        }

        const firstPlanning = planningEvents[0];
        if (firstPlanning) {
          const gw = Number(firstPlanning.id);
          const halfStart = gw <= 19 ? 1 : 20;
          add({
            cadence: 'half-season', keySuffix: `half${gw <= 19 ? 1 : 2}`,
            label: `Half ${gw <= 19 ? 1 : 2}`, startGameweek: halfStart, endGameweek: gw <= 19 ? 19 : 38,
            prizeCents: cents(process.env.SUPREME_HALF_SEASON_PRIZE_CENTS, 10000),
          });
          add({
            cadence: 'season', keySuffix: 'full-season', label: `${season} season`, startGameweek: 1, endGameweek: 38,
            prizeCents: cents(process.env.SUPREME_SEASON_PRIZE_CENTS, 30000),
          });
        }

        // Clash of the Captains only exists for the FPL-published September phase.
        // Every linked active user is eligible for free; score = captain raw GW points
        // + vice-captain raw GW points. Chips/multipliers do not alter this contest score.
        const september = phases.find((phase) => String(phase?.name || '').trim().toLowerCase() === 'september');
        if (september) {
          const start = Number(september.start_event || 0);
          const stop = Number(september.stop_event || 0);
          for (let gw = start; gw <= stop; gw += 1) {
            const event = eventById.get(gw);
            if (!event || !isFutureJoinableEvent(event)) continue;
            add({
              cadence: 'clash-captains', keySuffix: `gw${gw}`, label: `Gameweek ${gw}`,
              startGameweek: gw, endGameweek: gw,
              prizeCents: cents(process.env.SUPREME_CLASH_CAPTAINS_PRIZE_CENTS, 300),
              entryFeeCents: 0,
              scoringMode: 'captain-vice',
              entryMode: 'free-all',
            });
          }
        }

        return Array.from(definitions.values()).sort((a, b) => a.joinDeadlineAt - b.joinDeadlineAt || a.startGameweek - b.startGameweek);
      }

      async function resolveSystemCreator() {
        const configured = normaliseEmail(process.env.SUPREME_SYSTEM_USER_EMAIL);
        if (configured) {
          const found = await User.findOne({ email: configured });
          if (found) return found;
        }
        return User.findOne({ role: 'admin' }).sort({ createdAt: 1 });
      }

      function definitionCopy(def) {
        return {
          cadence: def.cadence,
          scoringMode: def.scoringMode || 'manager-points',
          entryMode: def.entryMode || 'subscription',
          periodLabel: def.periodLabel,
          startGameweek: def.startGameweek,
          endGameweek: def.endGameweek,
          joinDeadlineAt: def.joinDeadlineAt,
          prizeCents: def.prizeCents,
          entryFeeCents: def.entryFeeCents,
        };
      }

      function supremeCopyForDefinition(def) {
        const isWeekly = def.entryMode === 'weekly-flex';
        const isClash = def.entryMode === 'free-all' && def.scoringMode === 'captain-vice';
        if (isClash) {
          return {
            name: `Clash of the Captains — ${def.periodLabel}`,
            description: `Free September competition for every linked Supreme Fantasy League player. Your Clash score is your selected FPL captain's raw gameweek points plus your vice-captain's raw gameweek points. Highest score wins ${money(def.prizeCents)}.`,
            competitionType: 'clash-captains',
            ruleType: 'captain-vice-score',
            rules: [
              'Entry is free for every active Supreme Fantasy League user with a linked FPL manager before the official gameweek deadline.',
              'The competition is created only for gameweeks in FPL’s own September phase.',
              'Clash score equals the raw FPL points of the selected captain plus the raw FPL points of the selected vice-captain.',
              'Captain multipliers, Triple Captain multipliers and Bench Boost do not multiply the Clash score.',
              'Entry closes at the official FPL gameweek deadline.',
              'The competition closes only when FPL marks the gameweek finished and every fixture is finished.',
              'Prizes are paid after FPL marks the gameweek data_checked.',
              'If first place is tied, the published prize is split fairly among all tied winners.',
            ],
          };
        }
        if (isWeekly) {
          return {
            name: `Supreme weekly — ${def.periodLabel}`,
            description: `Official weekly Supreme competition for ${def.periodLabel}. Join with an eligible subscription or pay ${money(def.entryFeeCents)} for this gameweek. The guaranteed prize is ${money(def.prizeCents)}.`,
            competitionType: 'weekly',
            ruleType: 'weekly-entry',
            rules: [
              `Join with an eligible subscription or pay ${money(def.entryFeeCents)} for this weekly competition.`,
              'New entries close at the official FPL deadline for this gameweek.',
              'The competition closes only when FPL marks the gameweek finished and every fixture is finished.',
              'Prizes are paid after FPL marks the gameweek data_checked.',
              'Standings use qualifying FPL gameweek points.',
              'If first place is tied, the published prize is split fairly among all tied winners.',
            ],
          };
        }
        return {
          name: `Supreme ${def.cadence.replace('-', ' ')} — ${def.periodLabel}`,
          description: `Automatic Supreme Fantasy League competition for ${def.periodLabel}. Entry is included when the user's active subscription plan covers this competition.`,
          competitionType: def.cadence === 'bi-weekly' ? 'best-of-three' : def.cadence,
          ruleType: 'subscription',
          rules: [
            'Users with an eligible active subscription are automatically entered.',
            'New entries close at the official FPL deadline for the first gameweek in this competition.',
            'The competition closes only after FPL marks every included gameweek finished and every fixture is finished.',
            'Prizes are paid only after FPL marks every included gameweek data_checked.',
            'Standings use qualifying FPL gameweek points recorded across the competition range.',
            'If first place is tied, the published prize is split fairly among all tied winners.',
          ],
        };
      }

      async function ensureSupremeLeagues() {
        const [bootstrap, creator] = await Promise.all([fetchFplBootstrap(), resolveSystemCreator()]);
        if (!creator) throw new Error('Create an administrator or set SUPREME_SYSTEM_USER_EMAIL before Supreme leagues can be generated.');
        const definitions = supremeDefinitions(bootstrap);
        let created = 0;
        let reconciled = 0;

        for (const def of definitions) {
          const copy = supremeCopyForDefinition(def);
          let schedule = null;
          try {
            schedule = await getFplGameweekSchedule(def.endGameweek, { bootstrap, includeFixtures: true });
          } catch (error) {
            console.warn(`Could not load FPL fixture schedule for ${def.cycleKey}:`, error.message);
          }
          const lifecycleFields = {
            lastFixtureKickoffAt: schedule?.lastFixtureKickoffAt || null,
            finishedAt: schedule?.finished ? new Date() : null,
            dataCheckedAt: schedule?.finished && schedule?.dataChecked ? new Date() : null,
          };

          const existing = await SupremeLeagueMeta.findOne({ cycleKey: def.cycleKey });
          if (existing) {
            const league = await League.findById(existing.leagueId);
            if (league) {
              league.entryFeeCents = def.entryFeeCents;
              league.name = copy.name;
              league.description = copy.description;
              league.competitionType = copy.competitionType;
              league.ruleType = copy.ruleType;
              league.rules = copy.rules;
              league.projectedPrizeCents = def.prizeCents;
              league.displayedPrizeCents = def.prizeCents;
              league.guaranteedPrize = true;
              league.minimumParticipants = 1;
              league.maximumParticipants = Math.max(Number(league.maximumParticipants || 0), 100000);
              league.fplJoinDeadlineAt = def.joinDeadlineAt;
              if (lifecycleFields.lastFixtureKickoffAt) league.fplLastFixtureKickoffAt = lifecycleFields.lastFixtureKickoffAt;
              if (schedule?.finished !== true && !['settled', 'cancelled'].includes(league.status)) league.expiresAt = null;
              await league.save();
            }
            Object.assign(existing, definitionCopy(def));
            if (lifecycleFields.lastFixtureKickoffAt) existing.lastFixtureKickoffAt = lifecycleFields.lastFixtureKickoffAt;
            await existing.save();
            await LeagueAccessPolicy.updateOne(
              { leagueId: existing.leagueId },
              {
                $set: { visibility: 'public', joinDeadlineAt: def.joinDeadlineAt, allowLateJoin: false, createdBy: creator._id },
                $setOnInsert: { inviteCode: `SUP${crypto.randomBytes(4).toString('hex').toUpperCase()}` },
              },
              { upsert: true }
            );
            reconciled += 1;
            continue;
          }

          const league = await League.create({
            name: copy.name,
            description: copy.description,
            competitionType: copy.competitionType,
            ruleType: copy.ruleType,
            cadence: def.cadence,
            officialSupremeLeague: true,
            customLeague: false,
            status: new Date() < def.joinDeadlineAt ? 'open' : (schedule?.finished ? 'awaiting-review' : 'live'),
            startGameweek: def.startGameweek,
            endGameweek: def.endGameweek,
            currentGameweek: def.startGameweek,
            entryFeeCents: def.entryFeeCents,
            platformFeeBasisPoints: 0,
            grossPoolCents: 0,
            projectedPrizeCents: def.prizeCents,
            displayedPrizeCents: def.prizeCents,
            guaranteedPrize: true,
            minimumParticipants: 1,
            maximumParticipants: 100000,
            rules: copy.rules,
            createdBy: creator._id,
            expiresAt: schedule?.finished ? new Date() : null,
            fplJoinDeadlineAt: def.joinDeadlineAt,
            fplLastFixtureKickoffAt: lifecycleFields.lastFixtureKickoffAt,
            fplFinishedAt: lifecycleFields.finishedAt,
            fplDataCheckedAt: lifecycleFields.dataCheckedAt,
            completedAt: lifecycleFields.finishedAt,
          });
          await SupremeLeagueMeta.create({
            leagueId: league._id,
            ...definitionCopy(def),
            cycleKey: def.cycleKey,
            lastFixtureKickoffAt: lifecycleFields.lastFixtureKickoffAt,
            finishedAt: lifecycleFields.finishedAt,
            dataCheckedAt: lifecycleFields.dataCheckedAt,
          });
          await LeagueAccessPolicy.create({
            leagueId: league._id,
            visibility: 'public',
            inviteCode: `SUP${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
            joinDeadlineAt: def.joinDeadlineAt,
            allowLateJoin: false,
            createdBy: creator._id,
          });
          created += 1;
        }
        return { created, reconciled, definitions: definitions.length, planningHorizonDays: SUPREME_PLANNING_HORIZON_DAYS };
      }

      const entitlementMap = {
        monthly: new Set(['monthly']),
        plus: new Set(['bi-weekly', 'monthly']),
        'half-season': new Set(['weekly', 'bi-weekly', 'monthly', 'half-season']),
        halfSeason: new Set(['weekly', 'bi-weekly', 'monthly', 'half-season']),
        season: new Set(['weekly', 'bi-weekly', 'monthly', 'half-season', 'season']),
        'season-pass': new Set(['weekly', 'bi-weekly', 'monthly', 'half-season', 'season']),
      };

      function subscriptionEntitles(subscription, cadence, meta = null) {
        if (!subscription) return false;
        const code = String(subscription.planCode || '').trim();
        if (code === 'monthly' && cadence === 'monthly') {
          const metaCycleMatch = String(meta?.cycleKey || '').match(/:monthly:(\d{4}-\d{2})$/);
          const metaCycleKey = metaCycleMatch?.[1] || '';
          const storedCycleKey = String(subscription.monthlyCycleKey || '').trim();
          if (metaCycleKey && storedCycleKey && metaCycleKey !== storedCycleKey) return false;
          if (metaCycleKey && !storedCycleKey) {
            const anchor = subscription.activatedAt || subscription.startDate || subscription.createdAt;
            const inferred = anchor ? utcMonthKey(anchor) : '';
            if (inferred && inferred !== metaCycleKey) return false;
          }
        }
        if (Array.isArray(subscription.competitionsIncluded) && subscription.competitionsIncluded.includes(cadence)) return true;
        return entitlementMap[code]?.has(cadence) || false;
      }

      async function activeSubscriptionsForUsers(userIds, now = new Date()) {
        return Subscription.find({
          ...(userIds?.length ? { userId: { $in: userIds } } : {}),
          status: 'active',
          $or: [
            { endDate: { $gt: now } },
            { validUntil: { $gt: now } },
            { endDate: null, validUntil: null },
          ],
        }).lean();
      }

      async function enrollSubscribersInSupremeLeagues({ userId = null } = {}) {
        const now = new Date();
        const metas = await SupremeLeagueMeta.find({ settlementStatus: 'open', joinDeadlineAt: { $gt: now } }).lean();
        let enrolled = 0;
        let freeEntries = 0;
        let subscriptionEntries = 0;

        const userFilter = { role: 'user', status: 'active', fplManagerId: { $exists: true, $nin: ['', null] } };
        if (userId) userFilter._id = userId;
        const users = await User.find(userFilter).select('_id fplManagerId').lean();
        const userIds = users.map((user) => user._id);
        const subscriptions = await activeSubscriptionsForUsers(userIds, now);
        const subscriptionsByUser = new Map();
        for (const sub of subscriptions) {
          const key = String(sub.userId);
          if (!subscriptionsByUser.has(key)) subscriptionsByUser.set(key, []);
          subscriptionsByUser.get(key).push(sub);
        }

        for (const meta of metas) {
          for (const user of users) {
            const isFreeForAll = meta.entryMode === 'free-all';
            const includedBySubscription = (subscriptionsByUser.get(String(user._id)) || []).some((sub) => subscriptionEntitles(sub, meta.cadence, meta));
            if (!isFreeForAll && !includedBySubscription) continue;
            const exists = await LeagueEntry.exists({ leagueId: meta.leagueId, userId: user._id });
            if (exists) continue;
            await LeagueEntry.create({
              leagueId: meta.leagueId,
              userId: user._id,
              fantasyManagerId: user.fplManagerId,
              joinedAt: new Date(),
              paymentStatus: 'paid',
              eligibilityStatus: 'eligible',
              eligibilityReason: isFreeForAll ? 'Free Clash of the Captains entry' : 'Included with active subscription',
              currentScore: 0,
              currentRank: null,
              previousRank: null,
              prizeCents: 0,
              payoutStatus: 'not-applicable',
            });
            enrolled += 1;
            if (isFreeForAll) freeEntries += 1; else subscriptionEntries += 1;
          }
        }
        return { enrolled, freeEntries, subscriptionEntries, usersChecked: users.length };
      }

      async function enrollUserInOpenSupremeLeagues(userId) {
        if (!userId) return { enrolled: 0 };
        if (FPL_DATA_MODE !== 'public') return { enrolled: 0, skipped: true, reason: 'fpl-data-mode-not-public' };
        await ensureSupremeLeagues();
        return enrollSubscribersInSupremeLeagues({ userId });
      }

      async function managerPoints(managerId, startGameweek, endGameweek) {
        const response = await fetch(`${fplBaseUrl}/entry/${encodeURIComponent(managerId)}/history/`, { headers: { Accept: 'application/json' } });
        if (!response.ok) throw new Error(`FPL manager ${managerId} history returned HTTP ${response.status}.`);
        const payload = await response.json();
        return (payload.current || [])
          .filter((item) => Number(item.event) >= startGameweek && Number(item.event) <= endGameweek)
          .reduce((sum, item) => sum + Number(item.points || 0), 0);
      }

      async function captainVicePoints(managerId, gameweek) {
        const picks = await publicFantasyProvider.getManagerPicks(managerId, gameweek);
        const captain = (picks.lineup || []).find((player) => player.isCaptain);
        const viceCaptain = (picks.lineup || []).find((player) => player.isViceCaptain);
        if (!captain || !viceCaptain) throw new Error(`FPL picks for manager ${managerId} do not expose both captain and vice-captain for Gameweek ${gameweek}.`);
        return {
          score: Number(captain.points || 0) + Number(viceCaptain.points || 0),
          details: {
            scoringMode: 'captain-vice',
            gameweek: Number(gameweek),
            captain: { elementId: captain.elementId, name: captain.name, club: captain.club, points: Number(captain.points || 0) },
            viceCaptain: { elementId: viceCaptain.elementId, name: viceCaptain.name, club: viceCaptain.club, points: Number(viceCaptain.points || 0) },
          },
        };
      }

      async function creditPrize({ userId, leagueId, amountCents, reference, description = 'Supreme league prize' }) {
        const balanceField = walletBalanceField();
        const tx = await Transaction.findOneAndUpdate({ reference }, { $setOnInsert: {
          userId, leagueId, reference, type: 'prize', direction: 'credit', amountCents,
          currency: 'USD', provider: 'supreme', providerReference: reference, status: 'completed',
          description, metadata: { purpose: 'supreme-league-prize' },
        } }, { upsert: true, new: true });
        await updateWalletBalances(userId, { [balanceField]: amountCents, lifetimePrizesCents: amountCents }, `Supreme league prize ${reference}`, 'settleSupremeLeague', {}, `${reference}:wallet-credit`);
        return tx;
      }

      async function scoreSupremeEntry(entry, meta) {
        if (!entry.fantasyManagerId) throw new Error('No FPL manager ID is stored for this Supreme league entry.');
        if (meta.scoringMode === 'captain-vice') {
          return captainVicePoints(entry.fantasyManagerId, meta.endGameweek);
        }
        return { score: await managerPoints(entry.fantasyManagerId, meta.startGameweek, meta.endGameweek), details: { scoringMode: 'manager-points' } };
      }

      async function settleSupremeLeague(meta, bootstrap, options = {}) {
        const verified = await getVerifiedFplRangeState(meta.startGameweek, meta.endGameweek, { bootstrap });
        const now = new Date();
        meta.lastSettlementAttemptAt = now;
        if (!verified.finished) {
          meta.settlementStatus = 'open';
          meta.settlementLockId = '';
          meta.settlementLockedAt = null;
          meta.lastMaintenanceAt = now;
          meta.lastError = `Football is not verified finished (${verified.reason}).`;
          await meta.save();
          return { settled: false, reason: 'not-finished', verified };
        }

        const observedFinishedAt = meta.finishedAt || now;
        meta.finishedAt = observedFinishedAt;
        if (verified.lastFixtureKickoffAt) meta.lastFixtureKickoffAt = verified.lastFixtureKickoffAt;
        await League.updateOne(
          { _id: meta.leagueId, status: { $nin: ['settled', 'cancelled'] } },
          { $set: { status: 'awaiting-review', expiresAt: observedFinishedAt, fplFinishedAt: observedFinishedAt, completedAt: observedFinishedAt, ...(verified.lastFixtureKickoffAt ? { fplLastFixtureKickoffAt: verified.lastFixtureKickoffAt } : {}) } }
        );

        if (!verified.dataChecked && !options.forceDataChecked) {
          meta.settlementStatus = 'open';
          meta.settlementLockId = '';
          meta.settlementLockedAt = null;
          meta.lastMaintenanceAt = now;
          meta.lastError = '';
          await meta.save();
          return { settled: false, reason: 'awaiting-data-check', verified };
        }

        meta.dataCheckedAt = meta.dataCheckedAt || (verified.dataChecked ? now : null);
        meta.settlementStatus = 'scoring';
        meta.lastMaintenanceAt = now;
        if (options.manualBy) {
          meta.manualSettlementAt = now;
          meta.manualSettlementBy = options.manualBy;
          meta.manualSettlementReason = String(options.reason || 'Administrator settlement').slice(0, 500);
        }
        await meta.save();
        await League.updateOne({ _id: meta.leagueId }, { $set: { ...(meta.dataCheckedAt ? { fplDataCheckedAt: meta.dataCheckedAt } : {}) } });

        const entries = await LeagueEntry.find({
          leagueId: meta.leagueId,
          paymentStatus: { $in: ['paid', 'completed'] },
          eligibilityStatus: { $ne: 'ineligible' },
        });
        if (!entries.length) throw new Error('No eligible paid entries exist for this competition, so no prize can be settled.');

        const scored = [];
        const scoreFailures = [];
        for (const entry of entries) {
          try {
            const scoredEntry = await scoreSupremeEntry(entry, meta);
            entry.previousRank = entry.currentRank || null;
            entry.currentScore = Number(scoredEntry.score || 0);
            entry.scoreDetails = scoredEntry.details || {};
            entry.scoreThroughGameweek = meta.endGameweek;
            entry.lastScoreSyncAt = new Date();
            entry.scoreSyncStatus = 'success';
            entry.scoreSyncError = '';
            await entry.save();
            scored.push(entry);
          } catch (error) {
            entry.lastScoreSyncAt = new Date();
            entry.scoreSyncStatus = 'failed';
            entry.scoreSyncError = String(error.message || error).slice(0, 500);
            await entry.save();
            scoreFailures.push(`${entry._id}: ${entry.scoreSyncError}`);
          }
        }
        if (scoreFailures.length) {
          throw new Error(`Settlement paused because ${scoreFailures.length} eligible entr${scoreFailures.length === 1 ? 'y' : 'ies'} could not be scored from FPL. ${scoreFailures.slice(0, 3).join(' | ')}`);
        }

        scored.sort((a, b) => Number(b.currentScore || 0) - Number(a.currentScore || 0) || new Date(a.joinedAt || 0) - new Date(b.joinedAt || 0));
        let lastScore = null;
        let rank = 0;
        scored.forEach((entry, index) => {
          if (lastScore === null || Number(entry.currentScore) !== Number(lastScore)) rank = index + 1;
          entry.currentRank = rank;
          lastScore = entry.currentScore;
        });
        await Promise.all(scored.map((entry) => entry.save()));

        const topScore = Number(scored[0].currentScore || 0);
        const winners = scored.filter((entry) => Number(entry.currentScore || 0) === topScore);
        const baseSplit = Math.floor(Number(meta.prizeCents || 0) / winners.length);
        let remainder = Number(meta.prizeCents || 0) - baseSplit * winners.length;
        for (let index = 0; index < winners.length; index += 1) {
          const entry = winners[index];
          const amount = baseSplit + (remainder > 0 ? 1 : 0);
          if (remainder > 0) remainder -= 1;
          entry.prizeCents = amount;
          entry.payoutStatus = 'paid';
          await entry.save();
          await creditPrize({ userId: entry.userId, leagueId: meta.leagueId, amountCents: amount, reference: `SUP-PRIZE-${meta._id}-${entry.userId}`, description: meta.scoringMode === 'captain-vice' ? 'Clash of the Captains prize' : 'Supreme league prize' });
        }

        const league = await League.findById(meta.leagueId).lean();
        const winnerIds = new Set(winners.map((entry) => String(entry.userId)));
        for (const entry of scored) {
          const user = await User.findById(entry.userId).lean();
          if (!user?.email) continue;
          const won = winnerIds.has(String(entry.userId));
          await sendEmail({
            eventKey: `supreme-result:${meta._id}:${entry.userId}`,
            userId: entry.userId,
            to: user.email,
            category: won ? 'competition-win' : 'competition-result',
            subject: won ? `You finished on top — ${league?.name || 'Supreme competition'}` : `Final standings are in — ${league?.name || 'Supreme competition'}`,
            preheader: won ? 'Your prize has been credited and is available in your wallet.' : 'View your final standing.',
            title: won ? 'Congratulations — you finished on top' : 'The competition has been settled',
            tone: won ? 'success' : 'brand',
            message: won
              ? `<p style="margin:0;">You finished with the highest qualifying score${winners.length > 1 ? ' (tied for first)' : ''}. Your ${money(entry.prizeCents)} prize share has been credited to your Supreme wallet and is available for withdrawal.</p>`
              : `<p style="margin:0;">The final result is now available. Your score and rank remain available in your league history.</p>`,
            buttonLabel: 'View final standings',
            buttonUrl: `${appUrl}/app/leagues/${meta.leagueId}`,
            details: [
              { label: 'Competition', value: league?.name || meta.periodLabel },
              { label: 'Final rank', value: entry.currentRank || '—' },
              { label: 'Score', value: entry.currentScore || 0 },
              { label: 'Prize share', value: won ? money(entry.prizeCents) : money(0) },
            ],
          });
        }

        const settledAt = new Date();
        await League.updateOne({ _id: meta.leagueId }, { $set: {
          status: 'settled', completedAt: observedFinishedAt, expiresAt: observedFinishedAt, fplFinishedAt: observedFinishedAt,
          ...(meta.dataCheckedAt ? { fplDataCheckedAt: meta.dataCheckedAt } : {}),
        } });
        meta.settlementStatus = 'settled';
        meta.settledAt = settledAt;
        meta.winnerUserIds = winners.map((entry) => entry.userId);
        meta.splitAmountCents = baseSplit;
        meta.lastError = '';
        meta.settlementLockId = '';
        meta.settlementLockedAt = null;
        await meta.save();
        return { settled: true, winners: winners.length, prizeCents: meta.prizeCents, verified };
      }

      async function getSettlementDiagnostics(leagueId, { verifyLive = true } = {}) {
        const meta = await SupremeLeagueMeta.findOne({ leagueId }).lean();
        if (!meta) return null;
        let verified = null;
        if (verifyLive) {
          const bootstrap = await fetchFplBootstrap();
          verified = await getVerifiedFplRangeState(meta.startGameweek, meta.endGameweek, { bootstrap });
        }
        const entries = await LeagueEntry.find({ leagueId }).select('paymentStatus eligibilityStatus scoreSyncStatus scoreSyncError currentScore currentRank fantasyManagerId').lean();
        const eligible = entries.filter((entry) => ['paid', 'completed'].includes(entry.paymentStatus) && entry.eligibilityStatus !== 'ineligible');
        return {
          meta,
          verified: verified ? {
            finished: verified.finished,
            dataChecked: verified.dataChecked,
            reason: verified.reason,
            fixtureStates: verified.schedules.map((schedule) => ({ gameweek: schedule.gameweek, eventFinished: schedule.eventFinished, fixturesFinished: schedule.fixturesFinished, fixtureCount: schedule.fixtureCount, dataChecked: schedule.dataChecked, provisionalOnly: schedule.hasProvisionalOnlyFixtures })),
          } : {
            finished: Boolean(meta.finishedAt),
            dataChecked: Boolean(meta.dataCheckedAt),
            reason: 'Cached lifecycle state. Live FPL verification refreshes automatically after this page renders.',
            fixtureStates: [],
            cached: true,
          },
          participants: entries.length,
          eligibleParticipants: eligible.length,
          successfullyScored: eligible.filter((entry) => entry.scoreSyncStatus === 'success').length,
          scoreFailures: eligible.filter((entry) => entry.scoreSyncStatus === 'failed').map((entry) => entry.scoreSyncError).filter(Boolean),
          readyForAutomaticSettlement: Boolean((verified?.finished || meta.finishedAt) && (verified?.dataChecked || meta.dataCheckedAt) && eligible.length > 0),
          canManualSettle: Boolean((verified?.finished || meta.finishedAt) && eligible.length > 0),
        };
      }

      async function settleLeagueById(leagueId, options = {}) {
        const meta = await SupremeLeagueMeta.findOne({ leagueId });
        if (!meta) return { settled: false, reason: 'not-supreme-league' };
        if (meta.settlementStatus === 'settled') return { settled: true, alreadySettled: true, winners: meta.winnerUserIds?.length || 0 };
        const bootstrap = await fetchFplBootstrap();
        const verified = await getVerifiedFplRangeState(meta.startGameweek, meta.endGameweek, { bootstrap });
        if (!verified.finished) {
          const error = new Error('FPL has not verified that all football in this competition is finished. Manual settlement cannot bypass unfinished fixtures.');
          error.status = 409;
          throw error;
        }
        if (!verified.dataChecked && !options.forceDataChecked) return { settled: false, reason: 'awaiting-data-check', verified };

        const now = new Date();
        const staleLockBefore = new Date(now.getTime() - 15 * 60 * 1000);
        const lockId = createReference('SET');
        const locked = await SupremeLeagueMeta.findOneAndUpdate(
          {
            _id: meta._id,
            $or: [
              { settlementStatus: { $in: ['open', 'failed'] } },
              { settlementStatus: 'scoring', settlementLockedAt: { $lte: staleLockBefore } },
              { settlementStatus: 'scoring', settlementLockedAt: null },
            ],
          },
          { $set: { settlementStatus: 'scoring', settlementLockId: lockId, settlementLockedAt: now, lastSettlementAttemptAt: now, ...(verified.dataChecked ? { dataCheckedAt: meta.dataCheckedAt || now } : {}) } },
          { new: true }
        );
        if (!locked) return { settled: false, reason: 'settlement-already-running' };
        try {
          return await settleSupremeLeague(locked, bootstrap, options);
        } catch (error) {
          locked.settlementStatus = 'failed';
          locked.settlementLockId = '';
          locked.settlementLockedAt = null;
          locked.lastError = String(error.message || error).slice(0, 1000);
          locked.lastMaintenanceAt = new Date();
          await locked.save();
          throw error;
        }
      }

      async function settleFinishedSupremeLeagues() {
        const bootstrap = await fetchFplBootstrap();
        const candidates = await SupremeLeagueMeta.find({ settlementStatus: { $in: ['open', 'failed', 'scoring'] } }).select('_id leagueId startGameweek endGameweek settlementStatus settlementLockedAt');
        let settled = 0;
        let footballFinished = 0;
        let awaitingDataCheck = 0;
        let failed = 0;
        for (const candidate of candidates) {
          try {
            const verified = await getVerifiedFplRangeState(candidate.startGameweek, candidate.endGameweek, { bootstrap });
            if (!verified.finished) continue;
            footballFinished += 1;
            if (!verified.dataChecked) {
              awaitingDataCheck += 1;
              const observedFinishedAt = new Date();
              await League.updateOne({ _id: candidate.leagueId, status: { $nin: ['settled', 'cancelled'] } }, { $set: { status: 'awaiting-review', expiresAt: observedFinishedAt, fplFinishedAt: observedFinishedAt, completedAt: observedFinishedAt } });
              await SupremeLeagueMeta.updateOne({ _id: candidate._id }, { $set: { finishedAt: observedFinishedAt, settlementStatus: 'open', settlementLockId: '', settlementLockedAt: null, lastMaintenanceAt: new Date(), lastError: '' } });
              continue;
            }
            const result = await settleLeagueById(candidate.leagueId);
            if (result.settled) settled += 1;
          } catch (error) {
            failed += 1;
            await SupremeLeagueMeta.updateOne({ _id: candidate._id }, { $set: { settlementStatus: 'failed', settlementLockId: '', settlementLockedAt: null, lastError: String(error.message || error).slice(0, 1000), lastMaintenanceAt: new Date() } });
            console.error(`Supreme settlement failed for league ${candidate.leagueId}:`, error.message);
          }
        }
        return { settled, footballFinished, awaitingDataCheck, failed };
      }

      async function runMaintenance() {
        const result = {};
        result.referrals = await backfillReferralAccounts().then(() => processReferralRewards());
        if (FPL_DATA_MODE !== 'public') {
          result.supremeCreated = { created: 0, skipped: true, reason: 'FPL_DATA_MODE must be public.' };
          result.supremeEnrollment = { enrolled: 0, skipped: true };
          result.supremeSettlement = { settled: 0, skipped: true };
          return result;
        }
        result.supremeCreated = await ensureSupremeLeagues();
        result.supremeEnrollment = await enrollSubscribersInSupremeLeagues();
        result.supremeSettlement = await settleFinishedSupremeLeagues();
        return result;
      }
    
      let timer = null;
      function startTimers() {
        if (timer) return timer;
        setTimeout(() => runMaintenance().catch((error) => console.error('Initial local growth maintenance failed:', error.message)), 3000);
        timer = setInterval(() => runMaintenance().catch((error) => console.error('Local growth maintenance failed:', error.message)), maintenanceIntervalMs);
        if (typeof timer.unref === 'function') timer.unref();
        return timer;
      }
    
      if (requireAuth) {
        app.get('/api/referrals/me', requireAuth, async (req, res, next) => {
          try {
            await ensureReferralAccount(req.user);
            return success(res, await getReferralSummary(req.user._id));
          } catch (error) { next(error); }
        });
    
        app.get('/api/referrals/validate/:code', requireAuth, async (req, res, next) => {
          try {
            const account = await ReferralAccount.findOne({ code: normaliseCode(req.params.code) }).lean();
            return success(res, { valid: Boolean(account) });
          } catch (error) { next(error); }
        });
    
        app.get('/api/public-leagues', requireAuth, async (req, res, next) => {
          try {
            const now = new Date();
            const search = String(req.query.search || '').trim();
            const policies = await LeagueAccessPolicy.find({ visibility: 'public', joinDeadlineAt: { $gt: now } }).lean();
            const ids = policies.map((policy) => policy.leagueId);
            const leagueQuery = { _id: { $in: ids }, status: { $in: ['open', 'upcoming', 'live'] } };
            if (search) leagueQuery.$or = [
              { name: { $regex: search, $options: 'i' } },
              { description: { $regex: search, $options: 'i' } },
            ];
            const leagues = await League.find(leagueQuery).sort({ createdAt: -1 }).lean();
            const policyMap = new Map(policies.map((policy) => [String(policy.leagueId), policy]));
            return success(res, leagues.map((league) => ({ ...league, accessPolicy: policyMap.get(String(league._id)) || null })));
          } catch (error) { next(error); }
        });
    
        app.get('/api/leagues/:leagueId/access-policy', requireAuth, async (req, res, next) => {
          try {
            const policy = await getLeagueAccessPolicy(req.params.leagueId);
            return success(res, policy);
          } catch (error) { next(error); }
        });
    
        app.put('/api/leagues/:leagueId/access-policy', requireAuth, async (req, res, next) => {
          try {
            const league = await League.findById(req.params.leagueId);
            if (!league) return failure(res, 404, 'League not found.');
            const isOwner = String(league.createdBy) === String(req.user._id);
            const isAdmin = req.user.role === 'admin';
            if (!isOwner && !isAdmin) return failure(res, 403, 'Only the league creator or an administrator can change access settings.');
            const policy = await setLeagueAccessPolicy({
              league,
              creatorUserId: league.createdBy || req.user._id,
              visibility: req.body.visibility,
              inviteCode: req.body.inviteCode,
              joinDeadlineAt: req.body.joinDeadlineAt,
              allowLateJoin: req.body.allowLateJoin,
            });
            return success(res, policy);
          } catch (error) { next(error); }
        });
    
        app.get('/api/supreme-leagues', requireAuth, async (req, res, next) => {
          try {
            const refreshRequested = String(req.query.refresh || '') === '1';
            if (refreshRequested && FPL_DATA_MODE === 'public') {
              // This request is fired automatically after the cached competition list
              // is already visible. Do not make navigation wait on provisioning/FPL.
              await Promise.allSettled([
                refreshLeagueLifecycleIfStale(),
                ensureSupremeLeagues(),
              ]);
              await enrollSubscribersInSupremeLeagues({ userId: req.user._id }).catch((error) => console.warn('Supreme page enrollment failed:', error.message));
            }
            const metas = await SupremeLeagueMeta.find({}).sort({ joinDeadlineAt: 1, startGameweek: 1 }).lean();
            const leagueIds = metas.map((meta) => meta.leagueId);
            if (refreshRequested) {
              const joinedLeagueIds = await LeagueEntry.find({
                leagueId: { $in: leagueIds },
                userId: req.user._id,
                paymentStatus: { $in: ['paid', 'completed'] },
              }).distinct('leagueId');
              const refreshIds = joinedLeagueIds.slice(0, 6);
              await Promise.allSettled(refreshIds.map(async (joinedLeagueId) => {
                await settleLeagueById(joinedLeagueId, { trigger: 'supreme-page-background-refresh' }).catch(() => null);
                return syncLeagueScores(joinedLeagueId, { force: false });
              }));
            }
            const [leagues, entries] = await Promise.all([
              League.find({ _id: { $in: leagueIds } }).lean(),
              LeagueEntry.find({ leagueId: { $in: leagueIds }, userId: req.user._id }).lean(),
            ]);
            const leagueMap = new Map(leagues.map((item) => [String(item._id), item]));
            const entryMap = new Map(entries.map((item) => [String(item.leagueId), item]));
            const now = new Date();
            return success(res, metas.map((meta) => {
              const league = leagueMap.get(String(meta.leagueId)) || null;
              const myEntry = entryMap.get(String(meta.leagueId)) || null;
              const deadlineAt = meta.joinDeadlineAt ? new Date(meta.joinDeadlineAt) : null;
              const joined = myEntry?.paymentStatus === 'paid';
              const weeklyPaidEntry = meta.entryMode === 'weekly-flex' || (meta.cadence === 'weekly' && Number(league?.entryFeeCents ?? meta.entryFeeCents ?? 0) > 0);
              const joinOpen = Boolean(
                weeklyPaidEntry
                && !joined
                && deadlineAt
                && deadlineAt > now
                && ['open', 'upcoming'].includes(league?.status)
                && meta.settlementStatus === 'open'
              );
              return {
                ...meta,
                league,
                myEntry,
                joined,
                joinOpen,
                entryFeeCents: Number(league?.entryFeeCents ?? meta.entryFeeCents ?? 0),
                prizeCents: meta.cadence === 'clash-captains'
                  ? cents(process.env.SUPREME_CLASH_CAPTAINS_PRIZE_CENTS, 300)
                  : Number(meta.prizeCents || league?.displayedPrizeCents || 0),
                footballFinished: Boolean(meta.finishedAt || league?.fplFinishedAt || ['awaiting-review', 'settled'].includes(league?.status)),
                scoringFinalized: Boolean(meta.dataCheckedAt || league?.fplDataCheckedAt || meta.settlementStatus === 'settled'),
                includedWithSubscription: Boolean(joined && /included with active subscription/i.test(myEntry?.eligibilityReason || '')),
                freeEntry: meta.entryMode === 'free-all',
                paymentOptions: weeklyPaidEntry ? ['subscription', 'one-off'] : (meta.entryMode === 'free-all' ? ['free'] : ['subscription']),
                scoringMode: meta.scoringMode || 'manager-points',
                teamLinked: Boolean(req.user.fplManagerId),
                tieRule: 'If two or more users finish with the same highest score, the prize is split fairly among all tied winners.',
              };
            }));
          } catch (error) { next(error); }
        });
      }
    
      if (requireAdmin) {
        app.post('/api/internal/local/growth-maintenance', requireAuth, requireAdmin, async (req, res, next) => {
          try {
            return success(res, await runMaintenance());
          } catch (error) { next(error); }
        });
      }
    
      return {
        models: { ReferralAccount, LeagueAccessPolicy, SupremeLeagueMeta, GrowthEmailNotification },
        ensureReferralAccount,
        getReferralSummary,
        processReferralRewards,
        setLeagueAccessPolicy,
        getLeagueAccessPolicy,
        assertLeagueJoinAllowed,
        notifySupportTicketReceived,
        ensureSupremeLeagues,
        enrollSubscribersInSupremeLeagues,
        enrollUserInOpenSupremeLeagues,
        settleFinishedSupremeLeagues,
        settleLeagueById,
        getSettlementDiagnostics,
        runMaintenance,
        startTimers,
        sendEmail,
        sendScheduledUserEmails,
      };
    }
    
    module.exports = { installLocalGrowthSystem };
  })(inlineModule, inlineExports, require);

  return inlineModule.exports.installLocalGrowthSystem({
    app,
    mongoose,
    models: {
      User,
      UserProfile,
      Wallet,
      Transaction,
      Subscription,
      League,
      LeagueEntry,
      SupportTicket,
    },
    middleware: {
      requireAuth,
      requireAdmin,
    },
    helpers: {
      success,
      failure,
    },
  });
})();

// One-time/idempotent repair endpoint for existing Monthly Entry subscribers.
// It recalculates their FPL month window, then immediately reconciles Supreme entries.
app.post('/api/admin/maintenance/reconcile-monthly-subscriptions', requireAdmin, writeLimiter, async (req, res, next) => {
  try {
    const monthlySubscriptions = await reconcileMonthlySubscriptionWindows();
    let supremeCreated = null;
    let supremeStateRepair = null;
    let supremeEnrollment = null;

    if (FPL_DATA_MODE === 'public') {
      supremeCreated = await localGrowth.ensureSupremeLeagues();
      supremeStateRepair = await localGrowth.settleFinishedSupremeLeagues();
      supremeEnrollment = await localGrowth.enrollSubscribersInSupremeLeagues();
    }

    return success(res, {
      monthlySubscriptions,
      supremeCreated,
      supremeStateRepair,
      supremeEnrollment,
      message: 'Monthly subscription windows and eligible Supreme league entries were reconciled.',
    });
  } catch (error) { next(error); }
});

// -----------------------------------------------------------------------------
// Production static hosting and errors
// -----------------------------------------------------------------------------
if (IS_PRODUCTION && !IS_VERCEL) {
  const buildPath = path.join(__dirname, 'client', 'build');
  app.use(express.static(buildPath));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api/')) return next();
    return res.sendFile(path.join(buildPath, 'index.html'));
  });
}

function utcDayStart(value = new Date()) {
  const date = new Date(value);
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

async function claimDailyMaintenanceRun(now = new Date()) {
  const scheduledForUtc = utcDayStart(now);
  const runKey = `daily-maintenance:${scheduledForUtc.toISOString().slice(0, 10)}`;
  try {
    return await MaintenanceRun.create({
      _id: runKey,
      runKey,
      schedule: 'daily',
      scheduledForUtc,
      status: 'running',
      startedAt: now,
    });
  } catch (error) {
    if (error?.code !== 11000) throw error;

    // A failed invocation must not block maintenance for the rest of the UTC day.
    // Also reclaim a serverless run that was left "running" after a hard timeout.
    const staleBefore = new Date(now.getTime() - 30 * 60 * 1000);
    return MaintenanceRun.findOneAndUpdate(
      {
        _id: runKey,
        $or: [
          { status: 'failed' },
          { status: 'running', startedAt: { $lte: staleBefore } },
        ],
      },
      {
        $set: {
          status: 'running',
          startedAt: now,
          completedAt: null,
          failedAt: null,
          tasks: [],
          summary: {},
          error: '',
        },
      },
      { new: true }
    );
  }
}

async function runDailyMaintenanceTasks() {
  const monthlySubscriptions = await reconcileMonthlySubscriptionWindows();
  await expireSubscriptions();
  await reconcilePendingPaynowPayments();
  const walletPurchases = await reconcileProcessingWalletPurchases();
  const backfilledManagerIds = await backfillLeagueEntryFantasyManagerIds();
  const expiredLeagues = await updateExpiredLeagueStatuses();

  // Keep the financially important work near the front of the serverless run.
  // Provisioning, enrollment and settlement must not wait behind a potentially
  // large all-user team-sync batch; a function timeout must not strand prizes.
  const growth = await localGrowth.runMaintenance();
  const leagueSyncs = await syncActiveLeagueScores();
  const teamSnapshots = await refreshMemberTeamSnapshots();
  const engagementEmails = await localGrowth.sendScheduledUserEmails();
  return {
    tasks: [
      'reconcile-monthly-subscription-windows',
      'expire-subscriptions',
      'reconcile-paynow',
      'reconcile-wallet-purchases',
      'backfill-league-manager-ids',
      'update-expired-leagues',
      'growth-maintenance',
      'sync-league-scores',
      'refresh-member-team-snapshots',
      'send-account-league-gameweek-and-subscription-reminders',
    ],
    monthlySubscriptions,
    walletPurchases,
    backfilledManagerIds,
    expiredLeagues,
    leaguesScored: leagueSyncs.length,
    teamSnapshots,
    engagementEmails,
    growth,
  };
}

app.get('/api/internal/cron/league-lifecycle', async (req, res, next) => {
  try {
    if (!process.env.CRON_SECRET || req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) {
      return failure(res, 401, 'Unauthorized cron request.');
    }
    const leagueLifecycleUpdates = await updateExpiredLeagueStatuses();
    let supreme = {
      created: { created: 0, skipped: true },
      enrollment: { enrolled: 0, skipped: true },
      settlement: { settled: 0, skipped: true },
    };
    if (FPL_DATA_MODE === 'public') {
      supreme = {
        created: await localGrowth.ensureSupremeLeagues(),
        enrollment: await localGrowth.enrollSubscribersInSupremeLeagues(),
        settlement: await localGrowth.settleFinishedSupremeLeagues(),
      };
    }
    return success(res, {
      ranAt: new Date().toISOString(),
      leagueLifecycleUpdates,
      supreme,
    });
  } catch (error) { next(error); }
});

app.get('/api/internal/cron/maintenance', async (req, res, next) => {
  let run = null;
  try {
    if (!process.env.CRON_SECRET || req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) {
      return failure(res, 401, 'Unauthorized cron request.');
    }

    run = await claimDailyMaintenanceRun();
    if (!run) {
      return success(res, {
        skipped: true,
        reason: 'Daily maintenance has already been claimed for the current UTC date.',
        ranAt: new Date().toISOString(),
      });
    }

    const result = await runDailyMaintenanceTasks();
    const completedAt = new Date();
    await MaintenanceRun.updateOne(
      { _id: run._id, status: 'running' },
      {
        $set: {
          status: 'completed',
          completedAt,
          tasks: result.tasks,
          summary: result,
          error: '',
        },
      }
    );

    return success(res, {
      skipped: false,
      runKey: run.runKey,
      ranAt: completedAt.toISOString(),
      ...result,
    });
  } catch (error) {
    if (run?._id) {
      await MaintenanceRun.updateOne(
        { _id: run._id },
        {
          $set: {
            status: 'failed',
            failedAt: new Date(),
            error: String(error?.message || error).slice(0, 2000),
          },
        }
      ).catch((updateError) => console.error('Unable to record daily maintenance failure:', updateError.message));
    }
    return next(error);
  }
});

app.use('/api/*', (req, res) => failure(res, 404, 'API route not found.'));
app.use((err, req, res, next) => {
  const status = err.status || 500;
  console.error('Server error', req.requestId, err.message);
  const message = IS_PRODUCTION && status >= 500 ? 'An unexpected server error occurred.' : err.message || 'An unexpected server error occurred.';
  return failure(res, status, message);
});

function validateRuntimeConfiguration() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required.');
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET is required and must be at least 32 characters.');
  }
  if (PAYNOW_PAYMENTS && (!PAYNOW_INTEGRATION_ID || !PAYNOW_INTEGRATION_KEY)) {
    throw new Error('PAYNOW_INTEGRATION_ID and PAYNOW_INTEGRATION_KEY are required when PAYMENTS_MODE=paynow.');
  }
  if (ADMIN_NOTIFICATION_EMAIL && !/^\S+@\S+\.\S+$/.test(ADMIN_NOTIFICATION_EMAIL)) {
    throw new Error('ADMIN_NOTIFICATION_EMAIL must be a valid email address.');
  }

  // This block is intentionally strict, but it must not key off IS_PRODUCTION
  // alone: Vercel sets NODE_ENV=production for every deployment it builds
  // (Preview deployments included, not just the Production one), so gating
  // on IS_PRODUCTION would permanently block startup on Vercel the moment
  // any one of these isn't yet true — including while you're deliberately
  // still testing with mock payments / demo data. REAL_MONEY_ENABLED is the
  // explicit "we are actually going live" switch, so that's what triggers
  // the full readiness check instead.
  if (IS_PRODUCTION && String(process.env.REAL_MONEY_ENABLED || '').trim().toLowerCase() === 'true') {
    const problems = [];
    if (MOCK_PAYMENTS || !PAYNOW_PAYMENTS) problems.push('PAYMENTS_MODE must be paynow');
    if (PAYNOW_TEST_MODE) problems.push('PAYNOW_TEST_MODE must be false');
    if (process.env.REAL_MONEY_ENABLED !== 'true') problems.push('REAL_MONEY_ENABLED must be true');
    if (process.env.PAYMENT_PROVIDER_APPROVED !== 'true') problems.push('PAYMENT_PROVIDER_APPROVED must be true');
    if (MOCK_FANTASY || FPL_DATA_MODE !== 'public') problems.push('FPL_DATA_MODE must be public');
    if (process.env.FANTASY_DATA_AUTHORIZED !== 'true') problems.push('FANTASY_DATA_AUTHORIZED must be true');
    if (SEED_DEMO_DATA) problems.push('SEED_DEMO_DATA must be false');
    if (process.env.DEMO_USER_EMAIL || process.env.DEMO_USER_PASSWORD) problems.push('demo account variables must be removed');
    if (/localhost|127\.0\.0\.1/i.test(CLIENT_ORIGIN)) problems.push('CLIENT_ORIGIN must be a public HTTPS origin');
    if (!/^https:\/\//i.test(CLIENT_ORIGIN)) problems.push('CLIENT_ORIGIN must use HTTPS');
    if (!/^https:\/\//i.test(PUBLIC_API_URL)) problems.push('PUBLIC_API_URL must use HTTPS');
    if (process.env.EMAILS_ENABLED === 'false') problems.push('EMAILS_ENABLED must be true');
    if (!ADMIN_NOTIFICATION_EMAIL) problems.push('ADMIN_NOTIFICATION_EMAIL is required for signup and payment alerts');
    if (!ADMIN_SIGNUP_KEY || ADMIN_SIGNUP_KEY.length < 24) problems.push('ADMIN_SIGNUP_KEY must be at least 24 characters');
    if (process.env.LEGAL_APPROVAL_CONFIRMED !== 'true') problems.push('LEGAL_APPROVAL_CONFIRMED must be true after qualified counsel approval');
    if (problems.length) throw new Error(`Production configuration blocked: ${problems.join('; ')}.`);
  }
}

async function connectDatabase() {
  validateRuntimeConfiguration();
  if (mongoose.connection.readyState === 1) return mongoose.connection;

  if (!global.__sflMongoConnectionPromise) {
    global.__sflMongoConnectionPromise = mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: Number(process.env.MONGO_SERVER_SELECTION_TIMEOUT_MS || 10000),
      maxPoolSize: Number(process.env.MONGO_MAX_POOL_SIZE || 10),
      minPoolSize: 0,
      bufferCommands: false,
    }).catch((error) => {
      global.__sflMongoConnectionPromise = null;
      throw error;
    });
  }

  await global.__sflMongoConnectionPromise;
  return mongoose.connection;
}

async function prepareRuntime() {
  if (!global.__sflRuntimePromise) {
    global.__sflRuntimePromise = (async () => {
      await connectDatabase();

      // Vercel cold starts must stay lightweight. Running FPL bootstrap/fixture
      // reconciliation here made every new serverless instance behave like a cron
      // job before it could answer the user's request. Durable maintenance already
      // runs through /api/internal/cron/maintenance and the local maintenance script.
      if (IS_VERCEL) return true;

      await ensureDemoUser();
      if (SEED_DEMO_DATA) await ensureDemoLeagues();
      await backfillLeagueEntryFantasyManagerIds();
      await backfillLeagueExpiryDates();
      await updateExpiredLeagueStatuses();
      await expireSubscriptions();
      await reconcileProcessingWalletPurchases();
      return true;
    })().catch((error) => {
      global.__sflRuntimePromise = null;
      throw error;
    });
  }
  return global.__sflRuntimePromise;
}

async function start() {
  await prepareRuntime();
  const server = app.listen(PORT, () => {
    console.log(`Supreme Fantasy League server listening on port ${PORT}`);
    console.log(`Payments: ${PAYMENTS_MODE} | Fantasy data: ${FPL_DATA_MODE}`);
    if (PAYNOW_PAYMENTS && /localhost|127\.0\.0\.1/i.test(PAYNOW_RESULT_URL)) {
      console.warn('Paynow result callbacks cannot reach localhost. Set PUBLIC_API_URL or PAYNOW_RESULT_URL to a public HTTPS URL.');
    }
  });

  // In-process timers are used on long-running Node hosts; external cron remains the durable production trigger.
  if (!IS_VERCEL) {
    const subscriptionTimer = setInterval(
      async () => {
        try {
          await reconcileMonthlySubscriptionWindows();
          await expireSubscriptions();
        } catch (error) {
          console.error('Subscription validity check failed', error.message);
        }
      },
      SUBSCRIPTION_CHECK_INTERVAL_MS
    );
    const paynowTimer = setInterval(
      async () => {
        try {
          await reconcilePendingPaynowPayments();
          await reconcileProcessingWalletPurchases();
        } catch (error) {
          console.error('Payment reconciliation check failed', error.message);
        }
      },
      PAYNOW_PENDING_RECONCILE_INTERVAL_MS
    );
    const leagueScoreTimer = setInterval(
      () => syncActiveLeagueScores().catch((error) => console.error('League score sync failed', error.message)),
      FPL_LEAGUE_SYNC_INTERVAL_MS
    );
    const leagueLifecycleTimer = setInterval(
      () => updateExpiredLeagueStatuses().catch((error) => console.error('League lifecycle update failed', error.message)),
      Math.min(FPL_LEAGUE_SYNC_INTERVAL_MS, 15 * 60 * 1000)
    );
    const teamSnapshotTimer = setInterval(
      () => refreshMemberTeamSnapshots().catch((error) => console.error('Daily FPL team refresh failed', error.message)),
      24 * 60 * 60 * 1000
    );
    refreshMemberTeamSnapshots().catch((error) => console.error('Initial FPL team refresh failed', error.message));
    localGrowth.startTimers();
    subscriptionTimer.unref?.();
    paynowTimer.unref?.();
    leagueScoreTimer.unref?.();
    leagueLifecycleTimer.unref?.();
    teamSnapshotTimer.unref?.();
  }
  return server;
}

if (require.main === module) {
  start().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

module.exports = app;
module.exports.prepareRuntime = prepareRuntime;
module.exports.connectDatabase = connectDatabase;
module.exports.runGrowthMaintenance = async function runGrowthMaintenance() {
  await prepareRuntime();
  return localGrowth.runMaintenance();
};
