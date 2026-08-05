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
const FPL_LEAGUE_SCORE_CACHE_MINUTES = Math.max(1, Math.min(60, Number(process.env.FPL_LEAGUE_SCORE_CACHE_MINUTES || 10)));
const FPL_LEAGUE_SYNC_INTERVAL_MS = Math.max(60000, Number(process.env.FPL_LEAGUE_SYNC_INTERVAL_MS || 900000));
const FPL_LEAGUE_SYNC_LIMIT = Math.max(1, Math.min(50, Number(process.env.FPL_LEAGUE_SYNC_LIMIT || 10)));
const LEAGUE_ARCHIVE_GRACE_DAYS = Math.max(1, Math.min(30, Number(process.env.LEAGUE_ARCHIVE_GRACE_DAYS || 7)));
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
  lastValidityCheckAt: { type: Date, default: null },
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
  if (cached && cached.expiresAt > Date.now()) return cached.data;

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
  async getBootstrap() {
    return fetchFplJson('/bootstrap-static/');
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

function subscriptionDates(plan, startDate = new Date()) {
  const validUntil = new Date(startDate.getTime() + Number(plan.validityDays || 30) * 86400000);
  return {
    startDate,
    activatedAt: startDate,
    validUntil,
    endDate: validUntil,
    renewalDate: plan.billingInterval === 'monthly' ? validUntil : null,
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
      const dates = subscriptionDates(plan);
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
  const transactions = await Transaction.find({
    provider: 'paynow',
    status: { $in: ['pending', 'processing'] },
    'metadata.pollUrl': { $exists: true, $ne: '' },
    createdAt: { $gte: new Date(Date.now() - 48 * 60 * 60 * 1000) },
  }).sort({ updatedAt: 1 }).limit(25);
  for (const transaction of transactions) {
    try {
      const status = await pollPaynowTransaction(transaction);
      if (status) await processPaynowStatus(transaction, status);
    } catch (error) {
      console.error('Paynow reconciliation failed', transaction.reference, error.message);
    }
  }
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
  const participantCount = await LeagueEntry.countDocuments({ leagueId: league._id, paymentStatus: 'paid' });
  const reservedCount = await LeagueEntry.countDocuments({ leagueId: league._id, paymentStatus: { $in: ['paid', 'pending'] } });
  const grossPoolCents = participantCount * league.entryFeeCents;
  const platformFeeCents = league.customLeague ? Math.round(grossPoolCents * league.platformFeeBasisPoints / 10000) : 0;
  const projectedPrizeCents = league.customLeague ? grossPoolCents - platformFeeCents : league.projectedPrizeCents;
  let entry = null;
  if (userId) entry = await LeagueEntry.findOne({ leagueId: league._id, userId }).lean();
  const createdByCurrentUser = Boolean(userId && String(league.createdBy || '') === String(userId));
  const joined = entry?.paymentStatus === 'paid';
  const accessPolicy = await localGrowth.getLeagueAccessPolicy(league._id);
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
    joinDeadlineAt: accessPolicy?.joinDeadlineAt || league.expiresAt || null,
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
    return success(res, { manager });
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
    const [user, profile, snapshot, winStats] = await Promise.all([
      User.findById(userId)
        .select('fullName fantasyTeamName fplManagerId status createdAt')
        .lean(),
      UserProfile.findOne({ userId })
        .select('profilePicture')
        .lean(),
      TeamSnapshot.findOne({ userId, syncStatus: 'success' })
        .sort({ fetchedAt: -1, createdAt: -1 })
        .select('gameweek teamName managerName gameweekPoints totalPoints overallRank gameweekRank fetchedAt lastSuccessfulSyncAt')
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
          lastSyncedAt: snapshot?.lastSuccessfulSyncAt || snapshot?.fetchedAt || null,
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
  if (['settled', 'cancelled'].includes(league.status)) return true;
  return Boolean(league.expiresAt && new Date(league.expiresAt) <= now);
}

async function resolveLeagueExpiryDate(startGameweek, endGameweek) {
  try {
    if (FPL_DATA_MODE === 'public') {
      const bootstrap = await publicFantasyProvider.getBootstrap();
      const events = Array.isArray(bootstrap.events) ? bootstrap.events : [];
      const nextEvent = events.find((event) => Number(event.id) === Number(endGameweek) + 1);
      const endEvent = events.find((event) => Number(event.id) === Number(endGameweek));
      if (nextEvent?.deadline_time) return new Date(nextEvent.deadline_time);
      if (endEvent?.deadline_time) {
        return new Date(new Date(endEvent.deadline_time).getTime() + LEAGUE_ARCHIVE_GRACE_DAYS * 86400000);
      }
    }
  } catch (error) {
    console.warn('Could not resolve league expiry from FPL schedule:', error.message);
  }
  const durationWeeks = Math.max(1, Number(endGameweek) - Number(startGameweek) + 1);
  return new Date(Date.now() + (durationWeeks * 7 + LEAGUE_ARCHIVE_GRACE_DAYS) * 86400000);
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
  const leagues = await League.find({ expiresAt: null }).sort({ createdAt: 1 }).limit(limit);
  let updated = 0;
  for (const league of leagues) {
    league.expiresAt = await resolveLeagueExpiryDate(league.startGameweek, league.endGameweek);
    await league.save();
    updated += 1;
  }
  return updated;
}

async function updateExpiredLeagueStatuses() {
  const now = new Date();
  const result = await League.updateMany(
    {
      expiresAt: { $lte: now },
      status: { $in: ['open', 'full', 'upcoming', 'live'] },
    },
    {
      $set: {
        status: 'awaiting-review',
        completedAt: now,
      },
    }
  );
  return result.modifiedCount || 0;
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
      const history = await fantasyProvider.getManagerHistory(managerId);
      const relevant = history.filter((week) => week.gameweek >= league.startGameweek && week.gameweek <= scoreThroughGameweek);
      const score = relevant.reduce((total, week) => total + Number(week.points || 0), 0);
      const latest = relevant.length ? relevant[relevant.length - 1] : null;
      entry.currentScore = score;
      entry.scoreThroughGameweek = scoreThroughGameweek;
      entry.latestOverallRank = Number(latest?.rank || Number.MAX_SAFE_INTEGER);
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

async function buildTeamPayload(user) {
  if (!user.fplManagerId) return { linked: false, providerMode: FPL_DATA_MODE };

  const [latest, lastEntry] = await Promise.all([
    TeamSnapshot.findOne({ userId: user._id }).sort({ fetchedAt: -1 }).lean(),
    LeagueEntry.findOne({ userId: user._id }).sort({ updatedAt: -1 }).lean(),
  ]);

  let providerData = null;
  let providerWarning = '';
  try {
    providerData = await loadFantasyTeam(user.fplManagerId);
  } catch (error) {
    if (!latest) throw error;
    providerWarning = `${error.message} Showing the last successful sync instead.`;
  }

  const latestMatchesMode = latest && latest.providerMode === FPL_DATA_MODE;
  const snapshot = latestMatchesMode ? latest : providerData?.snapshot || latest;
  const manager = providerData?.manager || {
    managerId: user.fplManagerId,
    teamName: snapshot?.teamName || user.fantasyTeamName,
    managerName: snapshot?.managerName || '',
  };

  return {
    linked: true,
    manager,
    history: providerData?.history || [],
    snapshot,
    providerMode: FPL_DATA_MODE,
    providerWarning,
    lastConfirmation: lastEntry?.lastConfirmedGameweek || 0,
    inactivityStreak: lastEntry?.consecutiveInactiveGameweeks || 0,
  };
}

app.get('/api/team', requireAuth, async (req, res, next) => {
  try { return success(res, await buildTeamPayload(req.user)); } catch (error) { next(error); }
});

app.post('/api/team/sync', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    const managerId = normalizeManagerId(req.body.managerId || req.user.fplManagerId);
    const { manager, history, snapshot: normalizedSnapshot } = await loadFantasyTeam(managerId);

    await linkFantasyManagerToUser(req.user, managerId, manager.teamName);

    const snapshot = await TeamSnapshot.create({
      userId: req.user._id,
      ...normalizedSnapshot,
    });

    return success(res, {
      snapshot,
      history,
      manager,
      demo: MOCK_FANTASY,
      message: MOCK_FANTASY ? 'Fantasy team synchronised.' : 'Official FPL team synchronised successfully.',
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
app.get('/api/leagues', requireAuth, async (req, res, next) => {
  try {
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
      expiresAt: await resolveLeagueExpiryDate(start, end),
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
    if (!mongoose.isValidObjectId(req.params.leagueId)) return failure(res, 404, 'League not found.');
    const league = await League.findById(req.params.leagueId);
    if (!league) return failure(res, 404, 'League not found.');
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
  try { return success(res, { leaderboard: await getLeagueLeaderboard(req.params.leagueId, req.user._id) }); } catch (error) { next(error); }
});

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
      if (['completed', 'rejected', 'cancelled', 'reversed'].includes(existing.status)) {
        const subscription = await Subscription.findOne({ paymentTransactionId: existing._id }).lean();
        return success(res, await completedWalletPurchaseResponse(existing, { subscription }), 200);
      }
    }

    if (!transaction) {
      const pendingPaynow = await Transaction.exists({
        userId: req.user._id,
        type: 'subscription',
        provider: { $in: ['paynow', 'mock'] },
        status: { $in: ['pending', 'processing'] },
        'metadata.planCode': plan.planCode,
      });
      if (pendingPaynow) return failure(res, 409, 'A Paynow payment for this plan is still pending. Complete or allow it to expire before paying from the wallet.');

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

    const dates = subscriptionDates(plan);
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
      if (['completed', 'rejected', 'cancelled', 'reversed'].includes(existing.status)) {
        return success(res, await completedWalletPurchaseResponse(existing, { league: await leagueView(league, req.user._id) }), 200);
      }
    }

    entry = await LeagueEntry.findOne({ leagueId: league._id, userId: req.user._id });
    if (entry?.paymentStatus === 'paid') return failure(res, 409, 'You have already paid and joined this league.');
    if (entry?.paymentTransactionId) {
      const pending = await Transaction.findOne({ _id: entry.paymentTransactionId, provider: { $in: ['paynow', 'mock'] }, status: { $in: ['pending', 'processing'] } });
      if (pending) return failure(res, 409, 'A Paynow payment for this league is still pending. Complete or allow it to expire before paying from the wallet.');
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
        const dates = subscriptionDates(plan);
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
async function competitionLeaderboards(currentUserId) {
  const categories = [
    ['Weekly Cup', 'weekly'],
    ['Bi-Weekly Cup', 'bi-weekly'],
    ['Monthly Cup', 'monthly'],
    ['Half-Season Cup', 'half-season'],
    ['Season Cup', 'season'],
  ];

  const boards = [];
  for (const [name, key] of categories) {
    const league = await League.findOne({
      $or: [{ cadence: key }, { competitionType: key }],
      status: { $in: ['open', 'full', 'upcoming', 'live', 'awaiting-review', 'settled'] },
    }).sort({ officialSupremeLeague: -1, startGameweek: -1, createdAt: -1 });

    boards.push({
      key,
      name,
      leagueId: league?._id || null,
      leagueName: league?.name || '',
      status: league?.status || 'unavailable',
      scoreThroughGameweek: league?.scoreThroughGameweek || 0,
      lastScoredAt: league?.lastScoredAt || null,
      rows: league ? await getLeagueLeaderboard(league._id, currentUserId) : [],
    });
  }
  return boards;
}

app.get('/api/leaderboards', requireAuth, async (req, res, next) => {
  try {
    const [competitions, earnings] = await Promise.all([competitionLeaderboards(req.user._id), getEarningsLeaderboard(req.user._id, 10)]);
    return success(res, { competitions, earnings });
  } catch (error) { next(error); }
});

app.get('/api/dashboard', requireAuth, async (req, res, next) => {
  try {
    const [{ wallet }, team, subscription, gameState, entries, transactions, competitions, earningsLeaderboard] = await Promise.all([
      ensureUserResources(req.user._id),
      buildTeamPayload(req.user),
      currentSubscription(req.user._id),
      fantasyProvider.getGameState(),
      LeagueEntry.find({ userId: req.user._id }).populate('leagueId').sort({ updatedAt: -1 }).lean(),
      Transaction.find({ userId: req.user._id }).sort({ createdAt: -1 }).limit(5).lean(),
      competitionLeaderboards(req.user._id),
      getEarningsLeaderboard(req.user._id, 10),
    ]);

    const myLeagues = await Promise.all(entries.filter((e) => e.leagueId).map((entry) => leagueView(entry.leagueId, req.user._id)));
    const summary = {
      gameweekPoints: team.linked ? team.snapshot.gameweekPoints : 0,
      overallRank: team.linked ? team.snapshot.overallRank : null,
      activeLeagues: myLeagues.filter((l) => ['live', 'open', 'upcoming'].includes(l.status)).length,
      walletBalanceCents: wallet.availableBalanceCents,
      pendingBalanceCents: wallet.pendingBalanceCents,
      subscription: subscription?.planName || 'No active plan',
    };
    return success(res, {
      gameState,
      summary,
      myLeagues,
      team,
      transactions,
      pendingFinancialRequests: transactions.filter((t) => t.status === 'pending'),
      subscription,
      leaderboards: competitions,
      earningsLeaderboard,
      demoFunds: MOCK_PAYMENTS,
      providerAvailable: true,
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
    const monthStart = new Date(); monthStart.setUTCDate(1); monthStart.setUTCHours(0,0,0,0);
    const [users, newUsers, activeSubscriptions, usersInLeagues, leagueGroups, activeLeagues, finance, openTickets] = await Promise.all([
      User.countDocuments({ role: 'user' }), User.countDocuments({ role: 'user', createdAt: { $gte: monthStart } }), Subscription.countDocuments({ status: 'active' }), LeagueEntry.distinct('userId').then(x => x.length),
      League.aggregate([{ $group: { _id: '$competitionType', count: { $sum: 1 } } }, { $sort: { count: -1 } }]), League.countDocuments({ status: { $in: ['open','upcoming','live'] } }),
      Transaction.aggregate([{ $match: { status: 'completed' } }, { $group: { _id: { type: '$type', direction: '$direction' }, amountCents: { $sum: '$amountCents' }, count: { $sum: 1 } } }]),
      SupportTicket.countDocuments({ status: { $nin: ['resolved','closed'] } }),
    ]);
    const revenueTypes = new Set(['subscription','entry-fee','platform-fee','deposit']);
    const revenueCents = finance.filter(x => x._id.direction === 'credit' && revenueTypes.has(x._id.type)).reduce((s,x)=>s+x.amountCents,0);
    const payoutsDueCents = await Transaction.aggregate([{ $match: { type: { $in: ['withdrawal','prize'] }, status: { $in: ['pending','processing'] } } }, { $group: { _id: null, total: { $sum: '$amountCents' } } }]).then(x=>x[0]?.total||0);
    return success(res, { users, newUsers, activeSubscriptions, usersInLeagues, leagues: { total: leagueGroups.reduce((s,x)=>s+x.count,0), active: activeLeagues, byType: leagueGroups }, finances: { revenueCents, payoutsDueCents, breakdown: finance }, openTickets });
  } catch (error) { next(error); }
});

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

app.get('/api/admin/leagues/:id', requireAdmin, async (req,res,next)=>{try{
  const league=await League.findById(req.params.id).populate('createdBy','fullName email').lean(); if(!league)return failure(res,404,'League not found.');
  const members=await LeagueEntry.find({leagueId:league._id}).populate('userId','fullName email phone status fantasyTeamName').sort({currentRank:1,joinedAt:1}).lean();
  return success(res,{league,members,leaderboard:members.map(m=>({entryId:m._id,user:m.userId,rank:m.currentRank,score:m.currentScore,prizeCents:m.prizeCents,joinedAt:m.joinedAt,eligibilityStatus:m.eligibilityStatus}))});
}catch(error){next(error);}});

app.patch('/api/admin/leagues/:id/status', requireAdmin, writeLimiter, async (req, res, next) => {
  try {
    const allowed = ['draft', 'open', 'full', 'upcoming', 'live', 'awaiting-review', 'settled', 'cancelled'];
    if (!allowed.includes(req.body.status)) return failure(res, 400, 'Invalid league status.');
    const before = await League.findById(req.params.id).lean();
    if (!before) return failure(res, 404, 'League not found.');
    const league = await League.findByIdAndUpdate(
      req.params.id,
      { $set: { status: req.body.status, ...(req.body.status === 'settled' ? { completedAt: new Date() } : {}) } },
      { new: true }
    );
    await adminAudit(req, 'league.status.updated', 'League', league._id, { status: req.body.status });
    if (before.status !== 'settled' && league.status === 'settled') {
      await emailService.notifyLeagueOutcomes(league._id);
    }
    return success(res, { league });
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

app.get('/api/admin/users/:id', requireAdmin, async(req,res,next)=>{try{const [user,profile,wallet,subscriptions,entries,transactions]=await Promise.all([User.findById(req.params.id).lean(),UserProfile.findOne({userId:req.params.id}).lean(),Wallet.findOne({userId:req.params.id}).lean(),Subscription.find({userId:req.params.id}).sort({createdAt:-1}).lean(),LeagueEntry.find({userId:req.params.id}).populate('leagueId','name competitionType status').sort({joinedAt:-1}).lean(),Transaction.find({userId:req.params.id}).sort({createdAt:-1}).limit(200).lean()]); if(!user)return failure(res,404,'User not found.'); return success(res,{user,profile,wallet,subscriptions,entries,transactions});}catch(error){next(error);}});
app.patch('/api/admin/users/:id/status', requireAdmin, writeLimiter, async(req,res,next)=>{try{if(!['active','suspended','closed'].includes(req.body.status))return failure(res,400,'Invalid user status.'); const user=await User.findOneAndUpdate({_id:req.params.id,role:'user'},{$set:{status:req.body.status}},{new:true}); if(!user)return failure(res,404,'User not found.'); await adminAudit(req,'user.status.updated','User',user._id,{status:req.body.status}); return success(res,{user:adminPublicUser(user)});}catch(error){next(error);}});

app.get('/api/admin/transactions', requireAdmin, async(req,res,next)=>{try{const {page,limit}=pageOptions(req,50); const filter={}; if(req.query.type)filter.type=req.query.type;if(req.query.status)filter.status=req.query.status;if(req.query.provider)filter.provider=req.query.provider;if(req.query.direction)filter.direction=req.query.direction;if(req.query.minAmount)filter.amountCents={...(filter.amountCents||{}),$gte:Math.round(Number(req.query.minAmount)*100)};if(req.query.maxAmount)filter.amountCents={...(filter.amountCents||{}),$lte:Math.round(Number(req.query.maxAmount)*100)};if(req.query.search)filter.$or=[{reference:new RegExp(escapeRegex(req.query.search),'i')},{description:new RegExp(escapeRegex(req.query.search),'i')}]; const [rows,total]=await Promise.all([Transaction.find(filter).populate('userId','fullName email phone').populate('leagueId','name').sort({createdAt:-1}).skip((page-1)*limit).limit(limit).lean(),Transaction.countDocuments(filter)]); const summary=await Transaction.aggregate([{ $match:{}},{ $group:{_id:{type:'$type',status:'$status',provider:'$provider',direction:'$direction'},amountCents:{$sum:'$amountCents'},count:{$sum:1}}}]);return success(res,{rows,summary,pagination:{page,limit,total,pages:Math.ceil(total/limit)}});}catch(error){next(error);}});
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
        cadence: { type: String, enum: ['weekly', 'bi-weekly', 'monthly', 'half-season', 'season'], required: true, index: true },
        periodLabel: { type: String, required: true },
        startGameweek: { type: Number, required: true },
        endGameweek: { type: Number, required: true },
        joinDeadlineAt: { type: Date, required: true },
        prizeCents: { type: Number, required: true, min: 0 },
        settlementStatus: { type: String, enum: ['open', 'scoring', 'settled', 'failed'], default: 'open', index: true },
        settledAt: { type: Date, default: null },
        winnerUserIds: [{ type: Schema.Types.ObjectId, ref: 'User' }],
        splitAmountCents: { type: Number, default: 0 },
        lastMaintenanceAt: { type: Date, default: null },
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
        if (policy.joinDeadlineAt && new Date(policy.joinDeadlineAt) < new Date()) {
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
        const events = Array.isArray(bootstrap.events) ? bootstrap.events : [];
        if (!events.length) return [];
        const current = events.find((event) => event.is_current) || events.find((event) => event.is_next) || events[0];
        const gw = Number(current.id);
        const season = seasonKey(events);
        const defs = [];
        const eventById = (id) => events.find((event) => Number(event.id) === Number(id));
    
        const add = (cadence, keySuffix, label, startGameweek, endGameweek, prizeCents) => {
          const first = eventById(startGameweek);
          if (!first) return;
          defs.push({
            cadence,
            cycleKey: `${season}:${cadence}:${keySuffix}`,
            periodLabel: label,
            startGameweek,
            endGameweek,
            joinDeadlineAt: new Date(first.deadline_time),
            prizeCents,
          });
        };
    
        add('weekly', `gw${gw}`, `Gameweek ${gw}`, gw, gw, cents(process.env.SUPREME_WEEKLY_PRIZE_CENTS, 1000));
        const biStart = Math.floor((gw - 1) / 2) * 2 + 1;
        add('bi-weekly', `gw${biStart}-${Math.min(biStart + 1, 38)}`, `Gameweeks ${biStart}-${Math.min(biStart + 1, 38)}`, biStart, Math.min(biStart + 1, 38), cents(process.env.SUPREME_BIWEEKLY_PRIZE_CENTS, 1500));
    
        const currentDeadline = new Date(current.deadline_time);
        const monthlyEvents = events.filter((event) => {
          const date = new Date(event.deadline_time);
          return date.getUTCFullYear() === currentDeadline.getUTCFullYear() && date.getUTCMonth() === currentDeadline.getUTCMonth();
        });
        if (monthlyEvents.length) {
          add(
            'monthly',
            `${currentDeadline.getUTCFullYear()}-${String(currentDeadline.getUTCMonth() + 1).padStart(2, '0')}`,
            currentDeadline.toLocaleString('en-GB', { month: 'long', year: 'numeric', timeZone: 'UTC' }),
            Number(monthlyEvents[0].id),
            Number(monthlyEvents[monthlyEvents.length - 1].id),
            cents(process.env.SUPREME_MONTHLY_PRIZE_CENTS, 3000)
          );
        }
    
        const halfStart = gw <= 19 ? 1 : 20;
        add('half-season', `half${gw <= 19 ? 1 : 2}`, `Half ${gw <= 19 ? 1 : 2}`, halfStart, gw <= 19 ? 19 : 38, cents(process.env.SUPREME_HALF_SEASON_PRIZE_CENTS, 10000));
        add('season', 'full-season', `${season} season`, 1, 38, cents(process.env.SUPREME_SEASON_PRIZE_CENTS, 30000));
        return defs;
      }
    
      async function resolveSystemCreator() {
        const configured = normaliseEmail(process.env.SUPREME_SYSTEM_USER_EMAIL);
        if (configured) {
          const found = await User.findOne({ email: configured });
          if (found) return found;
        }
        return User.findOne({ role: 'admin' }).sort({ createdAt: 1 });
      }
    
      async function ensureSupremeLeagues() {
        const [bootstrap, creator] = await Promise.all([fetchFplBootstrap(), resolveSystemCreator()]);
        if (!creator) throw new Error('Create an administrator or set SUPREME_SYSTEM_USER_EMAIL before Supreme leagues can be generated.');
        const definitions = supremeDefinitions(bootstrap);
        let created = 0;
    
        for (const def of definitions) {
          const existing = await SupremeLeagueMeta.findOne({ cycleKey: def.cycleKey });
          if (existing) continue;
          const league = await League.create({
            name: `Supreme ${def.cadence.replace('-', ' ')} — ${def.periodLabel}`,
            description: `Automatic Supreme Fantasy League competition for ${def.periodLabel}. Entry is determined by the user's active subscription plan. In a draw, the published prize is split fairly among all tied winners.`,
            competitionType: def.cadence === 'bi-weekly' ? 'best-of-three' : def.cadence,
            ruleType: 'subscription',
            cadence: def.cadence,
            officialSupremeLeague: true,
            customLeague: false,
            status: new Date() < def.joinDeadlineAt ? 'open' : 'live',
            startGameweek: def.startGameweek,
            endGameweek: def.endGameweek,
            currentGameweek: def.startGameweek,
            entryFeeCents: 0,
            platformFeeBasisPoints: 0,
            grossPoolCents: 0,
            projectedPrizeCents: def.prizeCents,
            displayedPrizeCents: def.prizeCents,
            guaranteedPrize: true,
            minimumParticipants: 1,
            maximumParticipants: 100000,
            rules: [
              'Only users with an eligible active subscription are automatically entered.',
              'Standings use the qualifying FPL gameweek points recorded for the competition range.',
              'If two or more users finish with the same highest score, the prize is split fairly among all tied winners.',
              'Scores and results remain subject to provider availability and result review.',
            ],
            createdBy: creator._id,
          });
          await SupremeLeagueMeta.create({ leagueId: league._id, ...def });
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
        return { created, definitions: definitions.length };
      }
    
      const entitlementMap = {
        monthly: new Set(['monthly']),
        plus: new Set(['bi-weekly', 'monthly']),
        'half-season': new Set(['weekly', 'bi-weekly', 'monthly', 'half-season']),
        halfSeason: new Set(['weekly', 'bi-weekly', 'monthly', 'half-season']),
        season: new Set(['weekly', 'bi-weekly', 'monthly', 'half-season', 'season']),
        'season-pass': new Set(['weekly', 'bi-weekly', 'monthly', 'half-season', 'season']),
      };
    
      function subscriptionEntitles(subscription, cadence) {
        if (!subscription) return false;
        const code = String(subscription.planCode || '').trim();
        if (Array.isArray(subscription.competitionsIncluded) && subscription.competitionsIncluded.includes(cadence)) return true;
        return entitlementMap[code]?.has(cadence) || false;
      }
    
      async function enrollSubscribersInSupremeLeagues() {
        const now = new Date();
        const metas = await SupremeLeagueMeta.find({ settlementStatus: 'open', joinDeadlineAt: { $gt: now } }).lean();
        let enrolled = 0;
    
        for (const meta of metas) {
          const subscriptions = await Subscription.find({
            status: 'active',
            $or: [
              { endDate: { $gt: now } },
              { validUntil: { $gt: now } },
              { endDate: null, validUntil: null },
            ],
          }).lean();
    
          for (const sub of subscriptions) {
            if (!subscriptionEntitles(sub, meta.cadence)) continue;
            const user = await User.findById(sub.userId).lean();
            if (!user || user.status === 'suspended' || !user.fplManagerId) continue;
            const exists = await LeagueEntry.exists({ leagueId: meta.leagueId, userId: user._id });
            if (exists) continue;
            await LeagueEntry.create({
              leagueId: meta.leagueId,
              userId: user._id,
              fantasyManagerId: user.fplManagerId,
              joinedAt: new Date(),
              paymentStatus: 'paid',
              eligibilityStatus: 'eligible',
              eligibilityReason: 'Included with active subscription',
              currentScore: 0,
              currentRank: null,
              previousRank: null,
              prizeCents: 0,
              payoutStatus: 'not-applicable',
            });
            enrolled += 1;
          }
        }
        return { enrolled };
      }
    
      async function managerPoints(managerId, startGameweek, endGameweek) {
        const response = await fetch(`${fplBaseUrl}/entry/${encodeURIComponent(managerId)}/history/`, { headers: { Accept: 'application/json' } });
        if (!response.ok) throw new Error(`FPL manager ${managerId} history returned HTTP ${response.status}.`);
        const payload = await response.json();
        return (payload.current || [])
          .filter((item) => Number(item.event) >= startGameweek && Number(item.event) <= endGameweek)
          .reduce((sum, item) => sum + Number(item.points || 0), 0);
      }
    
      async function creditPrize({ userId, leagueId, amountCents, reference }) {
        const balanceField = walletBalanceField();
        const tx = await Transaction.findOneAndUpdate({ reference }, { $setOnInsert: {
          userId,
          leagueId,
          reference,
          type: 'prize',
          direction: 'credit',
          amountCents,
          currency: 'USD',
          provider: 'supreme',
          providerReference: reference,
          status: 'completed',
          description: 'Supreme league prize',
          metadata: { purpose: 'supreme-league-prize' },
        } }, { upsert: true, new: true });
        await updateWalletBalances(userId, { [balanceField]: amountCents, lifetimePrizesCents: amountCents }, `Supreme league prize ${reference}`, 'settleSupremeLeague', {}, `${reference}:wallet-credit`);
        return tx;
      }
    
      async function settleSupremeLeague(meta, bootstrap) {
        const events = bootstrap.events || [];
        const relevant = events.filter((event) => Number(event.id) >= meta.startGameweek && Number(event.id) <= meta.endGameweek);
        if (!relevant.length || relevant.some((event) => !event.finished)) return { settled: false, reason: 'not-finished' };
    
        meta.settlementStatus = 'scoring';
        meta.lastMaintenanceAt = new Date();
        await meta.save();
    
        const entries = await LeagueEntry.find({ leagueId: meta.leagueId, paymentStatus: { $in: ['paid', 'completed'] }, eligibilityStatus: { $ne: 'ineligible' } });
        const scored = [];
        for (const entry of entries) {
          if (!entry.fantasyManagerId) continue;
          try {
            const score = await managerPoints(entry.fantasyManagerId, meta.startGameweek, meta.endGameweek);
            entry.previousRank = entry.currentRank || null;
            entry.currentScore = score;
            await entry.save();
            scored.push(entry);
          } catch (error) {
            console.error(`Supreme score sync failed for entry ${entry._id}:`, error.message);
          }
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
    
        const topScore = scored.length ? Number(scored[0].currentScore || 0) : null;
        const winners = topScore === null ? [] : scored.filter((entry) => Number(entry.currentScore || 0) === topScore);
        const baseSplit = winners.length ? Math.floor(meta.prizeCents / winners.length) : 0;
        let remainder = winners.length ? meta.prizeCents - baseSplit * winners.length : 0;
    
        for (let index = 0; index < winners.length; index += 1) {
          const entry = winners[index];
          const amount = baseSplit + (remainder > 0 ? 1 : 0);
          if (remainder > 0) remainder -= 1;
          entry.prizeCents = amount;
          entry.payoutStatus = 'paid';
          await entry.save();
          await creditPrize({ userId: entry.userId, leagueId: meta.leagueId, amountCents: amount, reference: `SUP-PRIZE-${meta._id}-${entry.userId}` });
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
            preheader: won ? 'Your prize has been credited.' : 'View your final standing.',
            title: won ? 'Congratulations — you finished on top' : 'The competition has been settled',
            tone: won ? 'success' : 'brand',
            message: won
              ? `<p style="margin:0;">You finished with the joint-highest qualifying score. The prize was split fairly among all tied winners and your share has been credited to your wallet.</p>`
              : `<p style="margin:0;">The final result is now available. You did not finish among the winners this time, but your score and rank remain available in your league history.</p>`,
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
    
        await League.updateOne({ _id: meta.leagueId }, { $set: { status: 'settled', completedAt: new Date() } });
        meta.settlementStatus = 'settled';
        meta.settledAt = new Date();
        meta.winnerUserIds = winners.map((entry) => entry.userId);
        meta.splitAmountCents = baseSplit;
        meta.lastError = '';
        await meta.save();
        return { settled: true, winners: winners.length };
      }
    
      async function settleFinishedSupremeLeagues() {
        const bootstrap = await fetchFplBootstrap();
        const metas = await SupremeLeagueMeta.find({ settlementStatus: { $in: ['open', 'failed'] } }).select('_id');
        let settled = 0;
        for (const candidate of metas) {
          const meta = await SupremeLeagueMeta.findOneAndUpdate({ _id: candidate._id, settlementStatus: { $in: ['open', 'failed'] } }, { $set: { settlementStatus: 'scoring', settlementLockId: createReference('SET'), settlementLockedAt: new Date(), lastMaintenanceAt: new Date() } }, { new: true });
          if (!meta) continue;
          try {
            const result = await settleSupremeLeague(meta, bootstrap);
            if (result.settled) settled += 1;
          } catch (error) {
            meta.settlementStatus = 'failed';
            meta.lastError = String(error.message || error).slice(0, 1000);
            meta.lastMaintenanceAt = new Date();
            await meta.save();
            console.error(`Supreme settlement failed for ${meta.cycleKey}:`, meta.lastError);
          }
        }
        return { settled };
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
            const metas = await SupremeLeagueMeta.find({}).sort({ startGameweek: -1, createdAt: -1 }).lean();
            const leagueIds = metas.map((meta) => meta.leagueId);
            const [leagues, entries] = await Promise.all([
              League.find({ _id: { $in: leagueIds } }).lean(),
              LeagueEntry.find({ leagueId: { $in: leagueIds }, userId: req.user._id }).lean(),
            ]);
            const leagueMap = new Map(leagues.map((item) => [String(item._id), item]));
            const entryMap = new Map(entries.map((item) => [String(item.leagueId), item]));
            return success(res, metas.map((meta) => ({
              ...meta,
              league: leagueMap.get(String(meta.leagueId)) || null,
              myEntry: entryMap.get(String(meta.leagueId)) || null,
              tieRule: 'If two or more users finish with the same highest score, the prize is split fairly among all tied winners.',
            })));
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
        settleFinishedSupremeLeagues,
        runMaintenance,
        startTimers,
        sendEmail,
      };
    }
    
    module.exports = { installLocalGrowthSystem };
  })(inlineModule, inlineExports, require);

  return inlineModule.exports.installLocalGrowthSystem({
    app,
    mongoose,
    models: {
      User,
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

app.get('/api/internal/cron/maintenance', async (req, res, next) => {
  try {
    if (!process.env.CRON_SECRET || req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) {
      return failure(res, 401, 'Unauthorized cron request.');
    }
    await expireSubscriptions();
    await reconcilePendingPaynowPayments();
    const walletPurchases = await reconcileProcessingWalletPurchases();
    const backfilledManagerIds = await backfillLeagueEntryFantasyManagerIds();
    const backfilledLeagueExpiries = await backfillLeagueExpiryDates();
    const expiredLeagues = await updateExpiredLeagueStatuses();
    const leagueSyncs = await syncActiveLeagueScores();
    const growth = await localGrowth.runMaintenance();
    return success(res, {
      ranAt: new Date().toISOString(),
      tasks: ['expire-subscriptions', 'reconcile-paynow', 'reconcile-wallet-purchases', 'backfill-league-manager-ids', 'sync-league-scores'],
      walletPurchases,
      backfilledManagerIds,
      backfilledLeagueExpiries,
      expiredLeagues,
      leaguesScored: leagueSyncs.length,
      growth,
    });
  } catch (error) {
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
      () => expireSubscriptions().catch((error) => console.error('Subscription validity check failed', error.message)),
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
    const teamReminderTimer = setInterval(
      () => emailService.sendStaleTeamReminders().catch((error) => console.error('Team reminder check failed', error.message)),
      emailService.reminderCheckIntervalMs
    );
    emailService.sendStaleTeamReminders().catch((error) => console.error('Initial team reminder check failed', error.message));
    localGrowth.startTimers();
    subscriptionTimer.unref?.();
    paynowTimer.unref?.();
    leagueScoreTimer.unref?.();
    leagueLifecycleTimer.unref?.();
    teamReminderTimer.unref?.();
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
