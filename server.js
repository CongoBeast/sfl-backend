const path = require('path');
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
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:3000';
const CLIENT_ORIGINS = String(process.env.CLIENT_ORIGINS || CLIENT_ORIGIN)
  .split(',')
  .map((origin) => origin.trim().replace(/\/$/, ''))
  .filter(Boolean);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
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
});
const success = (res, data = {}, status = 200) => res.status(status).json({ success: true, data });
const failure = (res, status, message, errors = []) => res.status(status).json({ success: false, message, errors });

function validateProfilePicture(dataUrl) {
  if (!dataUrl) return { ok: true, value: '' };
  if (typeof dataUrl !== 'string' || !/^data:image\/(png|jpeg|webp);base64,/i.test(dataUrl)) {
    return { ok: false, message: 'Profile picture must be a PNG, JPEG, or WebP image.' };
  }
  const base64 = dataUrl.split(',')[1] || '';
  const bytes = Math.floor((base64.length * 3) / 4);
  if (bytes > 1.5 * 1024 * 1024) {
    return { ok: false, message: 'Profile picture must be 1.5 MB or smaller.' };
  }
  return { ok: true, value: dataUrl };
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

const subscriptionSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  planCode: { type: String, required: true },
  planName: { type: String, required: true },
  status: { type: String, default: 'pending-payment', enum: ['pending-payment', 'active', 'expired', 'replaced', 'cancelled', 'payment-failed'] },
  amountCents: { type: Number, required: true },
  billingInterval: { type: String, required: true },
  season: { type: String, default: 'Prototype Season' },
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
  providerSource: { type: String, default: 'prototype-mock' },
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
  monthly: { planCode: PLAN_CODES.MONTHLY, planName: 'Monthly Entry', amountCents: 100, billingInterval: 'monthly', validityDays: 30, competitionsIncluded: ['Supreme Monthly League'] },
  plus: { planCode: PLAN_CODES.PLUS, planName: 'Plus', amountCents: 500, billingInterval: 'monthly', validityDays: 30, competitionsIncluded: ['Monthly competitions', 'Selected bi-weekly competitions'] },
  halfSeason: { planCode: PLAN_CODES.HALF_SEASON, planName: 'Half-Season', amountCents: 2000, billingInterval: 'half-season', validityDays: 183, competitionsIncluded: ['Weekly competitions', 'Bi-weekly competitions', 'Monthly competitions', 'Half-season competition'] },
  season: { planCode: PLAN_CODES.SEASON, planName: 'Supreme Season Pass', amountCents: 4000, billingInterval: 'seasonal', validityDays: 365, competitionsIncluded: ['Qualifying Supreme-operated season-pass competitions'] },
});

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
const PAYMENT_METHODS = ['EcoCash', 'InnBucks', "O'mari", 'OneMoney', 'Bank Transfer', 'Visa', 'Mastercard'];

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
        'User-Agent': 'SupremeFantasyLeaguePrototype/1.0',
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
  throw new Error('FPL_DATA_MODE must be either "mock" or "public" in this prototype.');
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
      providerSource: FPL_DATA_MODE === 'public' ? 'fantasy.premierleague.com' : 'prototype-mock',
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
    const normalizedOrigin = origin.replace(/\/$/, '');
    if (CLIENT_ORIGINS.includes(normalizedOrigin)) return callback(null, true);
    const error = new Error('Origin is not allowed by CORS.');
    error.status = 403;
    return callback(error);
  },
}));
app.use(express.json({ limit: '2mb' }));
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

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies[COOKIE_NAME];
    if (!token) return failure(res, 401, 'Authentication required.');
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.sub);
    if (!user || user.status !== 'active') return failure(res, 401, 'Session is no longer valid.');
    req.user = user;
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
  return Transaction.findByIdAndUpdate(
    transaction._id,
    { $set: { status, 'metadata.pendingReleasedAt': new Date(), 'metadata.paynowStatus': reason } },
    { new: true }
  );
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

    return Transaction.findByIdAndUpdate(
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
  return Transaction.findByIdAndUpdate(
    transaction._id,
    { $set: { status: 'reversed', 'metadata.reversedAt': new Date(), 'metadata.paynowStatus': paynowData.status || 'Refunded' } },
    { new: true }
  );
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
    return Transaction.findByIdAndUpdate(
      transaction._id,
      { $set: { status: 'rejected', 'metadata.paynowStatus': paynowData.status || 'Failed' } },
      { new: true }
    );
  }
  return Transaction.findByIdAndUpdate(
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
  return {
    id: league._id,
    name: league.name,
    description: league.description,
    competitionType: league.competitionType,
    cadence: league.cadence,
    officialSupremeLeague: league.officialSupremeLeague,
    customLeague: league.customLeague,
    inviteOnly: league.inviteOnly,
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
    const { fullName, email, phone, dateOfBirth, password, confirmPassword, ageConfirmed, termsAccepted, privacyAccepted } = req.body;
    const errors = [];
    if (!fullName || fullName.trim().length < 2) errors.push('Enter your full name.');
    if (!/^\+?263\d{9}$/.test(String(phone || '').replace(/\s/g, ''))) errors.push('Enter a valid Zimbabwe phone number, for example +263771234567.');
    if (!isAdult(dateOfBirth) || ageConfirmed !== true) errors.push('You must be at least 18 years old.');
    if (!password || password.length < 8) errors.push('Password must be at least 8 characters.');
    if (password !== confirmPassword) errors.push('Passwords do not match.');
    if (!termsAccepted || !privacyAccepted) errors.push('Terms and Privacy acceptance are required.');
    if (errors.length) return failure(res, 400, 'Registration validation failed.', errors);

    const normalized = normalizeEmail(email);
    if (!/^\S+@\S+\.\S+$/.test(normalized)) return failure(res, 400, 'Enter a valid email address.');
    if (await User.exists({ email: normalized })) return failure(res, 409, 'An account with this email already exists.');

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ fullName, email: normalized, phone, dateOfBirth, passwordHash, ageConfirmed: true });
    const { profile } = await ensureUserResources(user._id);
    const token = signToken(user);
    setSessionCookie(res, token);
    await logAudit(req, 'auth.register', 'User', user._id, null, { email: user.email }, 'User registration');
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
    const { fullName, phone, dateOfBirth, city, address, country, currency, contactPreference, notificationPreferences, profilePicture } = req.body;
    const pictureValidation = validateProfilePicture(profilePicture);
    if (!pictureValidation.ok) return failure(res, 400, pictureValidation.message);
    if (dateOfBirth && !isAdult(dateOfBirth)) return failure(res, 400, 'The account holder must be at least 18 years old.');

    const beforeUser = publicUser(req.user);
    if (fullName) req.user.fullName = String(fullName).trim();
    if (phone) req.user.phone = String(phone).trim();
    if (dateOfBirth) req.user.dateOfBirth = new Date(dateOfBirth);
    if (country) req.user.country = country;
    if (currency) req.user.currency = currency;
    await req.user.save();

    const profile = await UserProfile.findOneAndUpdate(
      { userId: req.user._id },
      {
        $set: {
          ...(city !== undefined ? { city } : {}),
          ...(address !== undefined ? { address } : {}),
          ...(contactPreference ? { contactPreference } : {}),
          ...(notificationPreferences ? { notificationPreferences } : {}),
          ...(profilePicture !== undefined ? { profilePicture: pictureValidation.value } : {}),
          profileCompletion: clamp([req.user.fullName, req.user.email, req.user.phone, city, address, req.user.fplManagerId, profilePicture].filter(Boolean).length * 14, 20, 100),
        },
        $setOnInsert: { userId: req.user._id },
      },
      { upsert: true, new: true }
    );
    await logAudit(req, 'profile.update', 'User', req.user._id, beforeUser, publicUser(req.user, profile), 'User profile update');
    return success(res, { user: publicUser(req.user, profile), profile });
  } catch (error) { next(error); }
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
      message: MOCK_FANTASY ? 'Mock fantasy team synced.' : 'Public FPL team synced successfully.',
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
    const view = await leagueView(league, req.user._id);
    return success(res, {
      league: {
        ...view,
        inviteCode,
        canJoinWithCode: !view.joined && !view.isPast && ['open', 'upcoming'].includes(league.status),
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
    } = req.body;
    if (!name || !rulesAcknowledged) return failure(res, 400, 'League name and rules acknowledgement are required.');
    if (!req.user.fplManagerId) return failure(res, 400, 'Link your fantasy manager ID before creating and funding a league.');

    const inviteCode = normalizeInviteCode(requestedInviteCode);
    if (!isValidInviteCode(inviteCode)) {
      return failure(res, 400, 'Create a unique code using 6–16 letters, numbers or hyphens.');
    }
    if (await League.exists({ inviteCode })) return failure(res, 409, 'That league code is already in use. Choose another code.');

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
      inviteOnly: true,
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

    return success(res, {
      league: await leagueView(league, req.user._id),
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

// Legacy wallet-funded join route retained for public Supreme-operated leagues.
app.post('/api/leagues/:leagueId/join', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    const league = await League.findById(req.params.leagueId);
    if (!league) return failure(res, 404, 'League not found.');
    if (league.inviteOnly) return failure(res, 400, 'This league requires its unique code and Paynow checkout.');
    if (leagueIsPast(league)) return failure(res, 400, 'This league has closed and is available only in league history.');
    if (!['open', 'upcoming'].includes(league.status)) return failure(res, 400, 'This league is not open for entry.');
    if (await LeagueEntry.exists({ leagueId: league._id, userId: req.user._id, paymentStatus: 'paid' })) return failure(res, 409, 'You have already joined this league.');
    const count = await LeagueEntry.countDocuments({ leagueId: league._id, paymentStatus: 'paid' });
    if (count >= league.maximumParticipants) return failure(res, 400, 'This league is full.');
    if (!req.user.fplManagerId) return failure(res, 400, 'Link your fantasy manager ID before joining a league.');

    const wallet = await Wallet.findOneAndUpdate(
      { userId: req.user._id, availableBalanceCents: { $gte: league.entryFeeCents } },
      {
        $inc: { availableBalanceCents: -league.entryFeeCents, lifetimeEntryFeesCents: league.entryFeeCents },
        $set: {
          lastBalanceUpdateAt: new Date(),
          lastBalanceUpdateReason: `league-entry-funded:${league._id}`,
          lastBalanceUpdateFunction: 'joinLeagueEndpoint',
        },
      },
      { new: true }
    );
    if (!wallet) return failure(res, 400, 'Insufficient available balance.');

    try {
      await LeagueEntry.findOneAndUpdate(
        { leagueId: league._id, userId: req.user._id },
        {
          $set: {
            fantasyManagerId: req.user.fplManagerId,
            paymentStatus: 'paid',
            joinedAt: new Date(),
            currentScore: 0,
            currentRank: count + 1,
            previousRank: count + 1,
          },
        },
        { upsert: true, new: true }
      );
    } catch (error) {
      await Wallet.updateOne(
        { userId: req.user._id },
        {
          $inc: { availableBalanceCents: league.entryFeeCents, lifetimeEntryFeesCents: -league.entryFeeCents },
          $set: {
            lastBalanceUpdateAt: new Date(),
            lastBalanceUpdateReason: `league-entry-rollback:${league._id}`,
            lastBalanceUpdateFunction: 'joinLeagueEndpoint',
          },
        }
      );
      throw error;
    }

    await Transaction.create({
      userId: req.user._id, leagueId: league._id, reference: createReference('ENT'), type: 'entry-fee', direction: 'debit',
      amountCents: league.entryFeeCents, currency: 'USD', provider: 'internal-demo-ledger', status: 'completed', description: `Entry fee — ${league.name}`,
    });

    if (count + 1 >= league.maximumParticipants) league.status = 'full';
    await league.save();

    return success(res, { league: await leagueView(league, req.user._id), message: 'League joined successfully.' });
  } catch (error) {
    if (error?.code === 11000) return failure(res, 409, 'You have already joined this league.');
    next(error);
  }
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
    const netSpendingCents = wallet.lifetimeEntryFeesCents + wallet.lifetimeSubscriptionFeesCents - wallet.lifetimePrizesCents - wallet.lifetimeRefundsCents;
    return success(res, {
      wallet: { ...wallet.toObject(), netSpendingCents },
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
    return transaction;
  } catch (error) {
    await Transaction.findByIdAndUpdate(transaction._id, { $set: { status: 'rejected', 'metadata.initiationError': error.message } });
    if (subscription) await Subscription.findByIdAndUpdate(subscription._id, { $set: { status: 'payment-failed' } });
    if (leagueEntry) await LeagueEntry.findByIdAndUpdate(leagueEntry._id, { $set: { paymentStatus: 'failed' } });
    throw error;
  }
}

app.post('/api/payments/paynow/deposit', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    const amountCents = Math.round(Number(req.body.amount) * 100);
    if (!Number.isFinite(amountCents) || amountCents <= 0) return failure(res, 400, 'Enter a valid deposit amount.');
    if (!PAYNOW_EXPRESS_METHODS[req.body.method]) return failure(res, 400, 'Select a supported Paynow Express Checkout method.');
    const transaction = await createPaynowPaymentRecord({ req, type: 'deposit', amountCents, method: req.body.method, phone: req.body.phone });
    return success(res, { payment: paymentPublicView(transaction), demoWarning: MOCK_PAYMENTS ? 'Mock Paynow checkout completed. No real payment was processed.' : '' }, 201);
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
    if (!isCreator) {
      const inviteCode = normalizeInviteCode(req.body.inviteCode);
      if (!inviteCode || inviteCode !== league.inviteCode) return failure(res, 403, 'The league code is incorrect.');
      if (!['open', 'upcoming'].includes(league.status)) return failure(res, 400, 'This league is not open for new members.');
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
      league: await leagueView(league, req.user._id),
      demoWarning: MOCK_PAYMENTS ? 'Mock Paynow checkout completed. No real payment was processed.' : '',
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
    return success(res, { payment: paymentPublicView(transaction), demoWarning: MOCK_PAYMENTS ? 'Mock Paynow checkout completed. No real payment was processed.' : '' }, 201);
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
    return success(res, { payment: paymentPublicView(updated) });
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
    return success(res, { payment: paymentPublicView(transaction) });
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

// Legacy prototype endpoint. The replacement Wallet page uses /api/payments/paynow/deposit.
app.post('/api/deposits/request', requireAuth, writeLimiter, async (req, res) => {
  if (!MOCK_PAYMENTS) return failure(res, 409, 'Use the Paynow checkout endpoint for live deposits.');
  return failure(res, 410, 'This demo deposit endpoint has been replaced by Paynow checkout.');
});

app.post('/api/withdrawals/request', requireAuth, writeLimiter, async (req, res, next) => {
  try {
    const amountCents = Math.round(Number(req.body.amount) * 100);
    if (!Number.isFinite(amountCents) || amountCents <= 0) return failure(res, 400, 'Enter a valid withdrawal amount.');
    if (!PAYMENT_METHODS.includes(req.body.method)) return failure(res, 400, 'Select a supported destination method.');

    const idempotencyKey = String(req.headers['idempotency-key'] || '').trim();
    if (idempotencyKey) {
      const existing = await Transaction.findOne({ userId: req.user._id, type: 'withdrawal', 'metadata.idempotencyKey': idempotencyKey });
      if (existing) return success(res, { transaction: existing, demoWarning: MOCK_PAYMENTS ? 'Demo funds — no real payout processed.' : '' });
    }

    const wallet = await Wallet.findOneAndUpdate(
      { userId: req.user._id, availableBalanceCents: { $gte: amountCents } },
      {
        $inc: { availableBalanceCents: -amountCents, pendingBalanceCents: amountCents },
        $set: {
          lastBalanceUpdateAt: new Date(),
          lastBalanceUpdateReason: 'withdrawal-request-created',
          lastBalanceUpdateFunction: 'withdrawalsRequestEndpoint',
        },
      },
      { new: true }
    );
    if (!wallet) return failure(res, 400, 'Withdrawal amount cannot exceed the available balance.');

    let transaction;
    try {
      transaction = await Transaction.create({
        userId: req.user._id, reference: createReference('WDR'), type: 'withdrawal', direction: 'debit', amountCents, currency: 'USD',
        provider: 'manual-payout-review', status: 'pending', description: `Withdrawal request to ${req.body.method}`,
        metadata: { method: req.body.method, maskedAccount: String(req.body.maskedAccount || '').slice(-30), ...(idempotencyKey ? { idempotencyKey } : {}) },
      });
    } catch (error) {
      await updateWalletBalances(req.user._id, { availableBalanceCents: amountCents, pendingBalanceCents: -amountCents }, 'withdrawal-request-rollback', 'withdrawalsRequestEndpoint');
      throw error;
    }
    return success(res, { transaction, message: 'Withdrawal request created for manual payout review.' }, 201);
  } catch (error) { next(error); }
});

app.get('/api/subscription', requireAuth, async (req, res, next) => {
  try {
    const subscription = await currentSubscription(req.user._id);
    const history = await Subscription.find({ userId: req.user._id }).sort({ createdAt: -1 }).lean();
    return success(res, {
      subscription,
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

// Legacy mock subscription endpoint. The replacement Subscription page uses Paynow Express Checkout.
app.post('/api/subscription/select', requireAuth, writeLimiter, async (req, res) => {
  if (!MOCK_PAYMENTS) return failure(res, 409, 'Use the Paynow subscription checkout endpoint.');
  return failure(res, 410, 'This mock subscription endpoint has been replaced by Paynow checkout.');
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

app.patch('/api/admin/leagues/:id/status', requireAdmin, writeLimiter, async(req,res,next)=>{try{
  const allowed=['draft','open','full','upcoming','live','awaiting-review','settled','cancelled']; if(!allowed.includes(req.body.status))return failure(res,400,'Invalid league status.');
  const league=await League.findByIdAndUpdate(req.params.id,{$set:{status:req.body.status}},{new:true}); if(!league)return failure(res,404,'League not found.'); await adminAudit(req,'league.status.updated','League',league._id,{status:req.body.status}); return success(res,{league});
}catch(error){next(error);}});

app.post('/api/admin/leagues/:id/members', requireAdmin, writeLimiter, async(req,res,next)=>{try{
  const user=await User.findOne(req.body.userId?{_id:req.body.userId}:{email:normalizeEmail(req.body.email)}); if(!user)return failure(res,404,'User not found.');
  const entry=await LeagueEntry.findOneAndUpdate({leagueId:req.params.id,userId:user._id},{$setOnInsert:{fantasyManagerId:user.fplManagerId,joinedAt:new Date(),paymentStatus:req.body.paymentStatus||'admin-added'}},{new:true,upsert:true,setDefaultsOnInsert:true}); await adminAudit(req,'league.member.added','League',req.params.id,{userId:user._id}); return success(res,{entry},201);
}catch(error){if(error.code===11000)return failure(res,409,'User is already a member.');next(error);}});

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
    const backfilledManagerIds = await backfillLeagueEntryFantasyManagerIds();
    const backfilledLeagueExpiries = await backfillLeagueExpiryDates();
    const expiredLeagues = await updateExpiredLeagueStatuses();
    const leagueSyncs = await syncActiveLeagueScores();
    return success(res, {
      ranAt: new Date().toISOString(),
      tasks: ['expire-subscriptions', 'reconcile-paynow', 'backfill-league-manager-ids', 'sync-league-scores'],
      backfilledManagerIds,
      backfilledLeagueExpiries,
      expiredLeagues,
      leaguesScored: leagueSyncs.length,
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
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 16) {
    throw new Error('JWT_SECRET is required and should be at least 16 characters.');
  }
  if (PAYNOW_PAYMENTS && (!PAYNOW_INTEGRATION_ID || !PAYNOW_INTEGRATION_KEY)) {
    throw new Error('PAYNOW_INTEGRATION_ID and PAYNOW_INTEGRATION_KEY are required when PAYMENTS_MODE=paynow.');
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
    console.log(`Supreme Fantasy League server running on port ${PORT}`);
    console.log(`Payments: ${PAYMENTS_MODE} | Mock fantasy data: ${MOCK_FANTASY ? 'enabled' : 'disabled'}`);
    if (PAYNOW_PAYMENTS && /localhost|127\.0\.0\.1/i.test(PAYNOW_RESULT_URL)) {
      console.warn('Paynow result callbacks cannot reach localhost. Set PUBLIC_API_URL or PAYNOW_RESULT_URL to a public HTTPS URL.');
    }
  });

  // Persistent timers are valid for local/long-running Node hosting only.
  if (!IS_VERCEL) {
    const subscriptionTimer = setInterval(
      () => expireSubscriptions().catch((error) => console.error('Subscription validity check failed', error.message)),
      SUBSCRIPTION_CHECK_INTERVAL_MS
    );
    const paynowTimer = setInterval(
      () => reconcilePendingPaynowPayments().catch((error) => console.error('Paynow pending-payment check failed', error.message)),
      PAYNOW_PENDING_RECONCILE_INTERVAL_MS
    );
    const leagueScoreTimer = setInterval(
      () => syncActiveLeagueScores().catch((error) => console.error('League score sync failed', error.message)),
      FPL_LEAGUE_SYNC_INTERVAL_MS
    );
    subscriptionTimer.unref?.();
    paynowTimer.unref?.();
    leagueScoreTimer.unref?.();
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
