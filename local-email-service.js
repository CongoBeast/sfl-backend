'use strict';

const crypto = require('crypto');

function createLocalEmailService({
  mongoose,
  User,
  UserProfile,
  League,
  LeagueEntry,
  Transaction,
  TeamSnapshot,
  clientOrigin,
  normalizeEmail,
  normalizePaynowStatus,
}) {
  const { Schema } = mongoose;
  const EMAILS_ENABLED = String(process.env.EMAILS_ENABLED || 'false').trim().toLowerCase() === 'true';
  const RESENDER_API_KEY = String(process.env.RESENDER_API_KEY || '').trim();
  const SENDING_EMAIL = String(process.env.SENDING_EMAIL || '').trim();
  const ADMIN_NOTIFICATION_EMAIL = String(process.env.ADMIN_NOTIFICATION_EMAIL || '').trim().toLowerCase();
  const EMAIL_REQUEST_TIMEOUT_MS = Math.max(3000, Math.min(30000, Number(process.env.EMAIL_REQUEST_TIMEOUT_MS || 12000)));
  const TEAM_INACTIVITY_DAYS = Math.max(7, Math.min(90, Number(process.env.EMAIL_TEAM_INACTIVITY_DAYS || 14)));
  const TEAM_REMINDER_COOLDOWN_DAYS = Math.max(1, Math.min(30, Number(process.env.EMAIL_TEAM_REMINDER_COOLDOWN_DAYS || 7)));
  const REMINDER_CHECK_INTERVAL_MS = Math.max(60 * 60 * 1000, Number(process.env.EMAIL_REMINDER_CHECK_INTERVAL_MS || 6 * 60 * 60 * 1000));

  if (EMAILS_ENABLED) {
    const missing = [];
    if (!RESENDER_API_KEY) missing.push('RESENDER_API_KEY');
    if (!SENDING_EMAIL) missing.push('SENDING_EMAIL');
    if (missing.length) {
      throw new Error(`Email notifications are enabled but these environment variables are missing: ${missing.join(', ')}`);
    }
    if (!SENDING_EMAIL.includes('@')) {
      throw new Error('SENDING_EMAIL must contain a valid sender address, optionally with a display name.');
    }
    if (ADMIN_NOTIFICATION_EMAIL && !/^\S+@\S+\.\S+$/.test(ADMIN_NOTIFICATION_EMAIL)) {
      throw new Error('ADMIN_NOTIFICATION_EMAIL must be a valid email address.');
    }
  }

  const schema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: 'User', default: null, index: true },
    recipient: { type: String, required: true, lowercase: true, trim: true, index: true },
    eventType: { type: String, required: true, index: true },
    dedupeKey: { type: String, required: true, unique: true, index: true },
    subject: { type: String, required: true },
    status: { type: String, default: 'queued', enum: ['queued', 'sending', 'sent', 'failed', 'skipped'] },
    resendEmailId: { type: String, default: '' },
    attempts: { type: Number, default: 0 },
    error: { type: String, default: '' },
    metadata: { type: Schema.Types.Mixed, default: {} },
    sentAt: { type: Date, default: null },
  }, { timestamps: true });

  const EmailNotification = mongoose.models.EmailNotification
    || mongoose.model('EmailNotification', schema);

  const brand = Object.freeze({
    name: 'Supreme Fantasy League',
    accent: '#cb2957',
    accentBright: '#ec3e70',
    ink: '#050505',
    surface: '#f5f5f7',
    muted: '#6f6f76',
  });

  const escapeHtml = (value = '') => String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

  const appLink = (pathname = '/') => {
    const base = `${String(clientOrigin || 'http://localhost:3000').replace(/\/$/, '')}/`;
    return new URL(String(pathname || '/').replace(/^\//, ''), base).toString();
  };

  const formatUsd = (amountCents = 0) => `$${(Number(amountCents || 0) / 100).toFixed(2)}`;
  const formatDateTime = (value) => value
    ? new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
    : 'Not available';

  function renderEmailTemplate({ eyebrow, title, intro, content = '', actionLabel, actionUrl, footerNote = '' }) {
    const safeActionUrl = actionUrl ? escapeHtml(actionUrl) : '';
    return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title></head>
<body style="margin:0;padding:0;background:${brand.surface};font-family:Inter,Arial,Helvetica,sans-serif;color:${brand.ink};">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">${escapeHtml(intro)}</div>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:${brand.surface};">
<tr><td align="center" style="padding:28px 14px;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:620px;background:#fff;border-radius:24px;overflow:hidden;box-shadow:0 18px 55px rgba(5,5,5,.12);">
<tr><td style="padding:26px 30px;background:#151116;color:#fff;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"><tr>
<td><div style="display:inline-block;width:42px;height:42px;line-height:42px;text-align:center;border-radius:13px;background:${brand.accent};font-weight:900;font-size:18px;box-shadow:0 10px 26px rgba(203,41,87,.38);">S</div></td>
<td align="right" style="font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:rgba(255,255,255,.68);">${escapeHtml(brand.name)}</td>
</tr></table>
<div style="margin-top:28px;font-size:12px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:#ff9fbd;">${escapeHtml(eyebrow)}</div>
<h1 style="margin:10px 0 0;font-size:30px;line-height:1.15;letter-spacing:-.03em;color:#fff;">${escapeHtml(title)}</h1>
</td></tr>
<tr><td style="padding:30px;">
<p style="margin:0 0 20px;font-size:16px;line-height:1.7;color:#34343a;">${escapeHtml(intro)}</p>
${content}
${actionLabel && safeActionUrl ? `<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin-top:28px;"><tr><td style="border-radius:14px;background:${brand.accent};box-shadow:0 10px 24px rgba(203,41,87,.25);"><a href="${safeActionUrl}" style="display:inline-block;padding:14px 22px;color:#fff;text-decoration:none;font-size:14px;font-weight:900;">${escapeHtml(actionLabel)} &rarr;</a></td></tr></table>` : ''}
${footerNote ? `<p style="margin:24px 0 0;padding-top:20px;border-top:1px solid #e7e7ea;font-size:12px;line-height:1.6;color:${brand.muted};">${escapeHtml(footerNote)}</p>` : ''}
</td></tr>
<tr><td style="padding:18px 30px;background:#0a0a0b;color:rgba(255,255,255,.58);font-size:11px;line-height:1.6;">This is a transactional message from ${escapeHtml(brand.name)}. We will never contact you by SMS, WhatsApp, email or telephone to ask for an OTP, password, PIN, CVC or a direct transfer of funds. Initiate payments only inside the official platform.</td></tr>
</table></td></tr></table></body></html>`;
  }

  function detailRows(rows = []) {
    const items = rows.filter((row) => row && row.label && row.value !== undefined && row.value !== null && row.value !== '');
    if (!items.length) return '';
    return `<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border:1px solid #e7e7ea;border-radius:16px;overflow:hidden;background:#fafafa;">${items.map((row, index) => `<tr><td style="padding:13px 15px;${index ? 'border-top:1px solid #e7e7ea;' : ''}font-size:12px;font-weight:800;color:#77777e;text-transform:uppercase;letter-spacing:.05em;">${escapeHtml(row.label)}</td><td align="right" style="padding:13px 15px;${index ? 'border-top:1px solid #e7e7ea;' : ''}font-size:14px;font-weight:800;color:#151116;">${escapeHtml(row.value)}</td></tr>`).join('')}</table>`;
  }

  async function preferenceAllows(userId, category) {
    if (category === 'transactional') return true;
    const profile = await UserProfile.findOne({ userId }).select('notificationPreferences').lean();
    const preferences = profile?.notificationPreferences || {};
    if (preferences.emailNotifications === false) return false;
    if (category === 'league' && preferences.leagueReminders === false) return false;
    if (category === 'result' && preferences.results === false) return false;
    if (category === 'team-reminder' && preferences.deadlineReminders === false) return false;
    return true;
  }

  async function sendBrandedEmail({
    user = null,
    recipientEmail = '',
    bypassPreferences = false,
    eventType,
    dedupeKey,
    subject,
    eyebrow,
    title,
    intro,
    content,
    actionLabel,
    actionUrl,
    footerNote,
    category = 'transactional',
    metadata = {},
  }) {
    if (!EMAILS_ENABLED) return { skipped: true };
    const recipient = normalizeEmail(recipientEmail || user?.email || '');
    if (!recipient) return { skipped: true, reason: 'missing-recipient' };
    if (user?._id && !bypassPreferences && !(await preferenceAllows(user._id, category))) return { skipped: true, reason: 'preference' };

    const existing = await EmailNotification.findOne({ dedupeKey }).lean();
    if (existing?.status === 'sent' || existing?.status === 'sending' || existing?.attempts >= 3) return existing;

    const notification = await EmailNotification.findOneAndUpdate(
      { dedupeKey },
      {
        $setOnInsert: { userId: user?._id || null, recipient, eventType, dedupeKey },
        $set: { status: 'sending', error: '', subject, metadata },
        $inc: { attempts: 1 },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), EMAIL_REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${RESENDER_API_KEY}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `sfl-${crypto.createHash('sha256').update(dedupeKey).digest('hex').slice(0, 48)}`,
        },
        body: JSON.stringify({
          from: SENDING_EMAIL,
          to: [recipient],
          subject,
          html: renderEmailTemplate({ eyebrow, title, intro, content, actionLabel, actionUrl, footerNote }),
          text: `${title}\n\n${intro}${actionUrl ? `\n\n${actionLabel}: ${actionUrl}` : ''}`,
        }),
        signal: controller.signal,
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.id) {
        throw new Error(payload?.message || payload?.error?.message || `Resend returned HTTP ${response.status}.`);
      }
      notification.status = 'sent';
      notification.resendEmailId = payload.id;
      notification.sentAt = new Date();
      notification.error = '';
      await notification.save();
      return notification;
    } catch (error) {
      notification.status = 'failed';
      notification.error = error.name === 'AbortError' ? 'Resend request timed out.' : String(error.message || error);
      await notification.save();
      console.error('Email notification failed', eventType, recipient, notification.error);
      return notification;
    } finally {
      clearTimeout(timeout);
    }
  }

  async function notifyWelcome(user) {
    return sendBrandedEmail({
      user,
      eventType: 'account.welcome',
      dedupeKey: `account-welcome:${user._id}`,
      subject: `Your Supreme stage is ready — welcome, ${String(user.fullName || 'manager').split(' ')[0]}`,
      eyebrow: 'Your account is live',
      title: `Welcome to the Supreme stage, ${String(user.fullName || 'manager').split(' ')[0]}`,
      intro: 'Your account is ready. Link your FPL manager ID, review the competition rules and choose the qualifying league that matches how you manage.',
      content: detailRows([
        { label: 'Account email', value: user.email },
        { label: 'Created', value: formatDateTime(user.createdAt || new Date()) },
        { label: 'Currency', value: user.currency || 'USD' },
      ]),
      actionLabel: 'Open your dashboard',
      actionUrl: appLink('/app/dashboard'),
      footerNote: 'Your FPL manager ID can only be linked to one Supreme Fantasy League account.',
    });
  }


  async function notifyAdminWelcome(user) {
    return sendBrandedEmail({
      user,
      bypassPreferences: true,
      eventType: 'admin.welcome',
      dedupeKey: `admin-welcome:${user._id}`,
      subject: `Your Supreme admin access is ready — ${String(user.fullName || 'administrator').split(' ')[0]}`,
      eyebrow: 'Administrator onboarding',
      title: 'Welcome to Supreme operations',
      intro: 'Your administrator account is active. Use it only for authorised operational work and protect it with the same care as a financial account.',
      content: detailRows([
        { label: 'Administrator', value: user.fullName },
        { label: 'Email', value: user.email },
        { label: 'Created', value: formatDateTime(user.createdAt || new Date()) },
        { label: 'Role', value: 'Administrator' },
      ]),
      actionLabel: 'Open the admin console',
      actionUrl: appLink('/admin/login'),
      footerNote: 'Never share the administrator setup key, password, session cookie, OTP, payment credentials or internal account information. Review every wallet adjustment and withdrawal status change before submitting it.',
    });
  }

  async function notifyOwnerUserSignup(user) {
    if (!ADMIN_NOTIFICATION_EMAIL) return { skipped: true, reason: 'admin-notification-email-not-configured' };
    return sendBrandedEmail({
      recipientEmail: ADMIN_NOTIFICATION_EMAIL,
      bypassPreferences: true,
      eventType: 'operations.user-signup',
      dedupeKey: `operations-user-signup:${user._id}`,
      subject: `New Supreme member: ${user.fullName}`,
      eyebrow: 'New account',
      title: 'A new user joined Supreme',
      intro: `${user.fullName} created a Supreme Fantasy League account.`,
      content: detailRows([
        { label: 'Name', value: user.fullName },
        { label: 'Email', value: user.email },
        { label: 'Phone', value: user.phone },
        { label: 'Joined', value: formatDateTime(user.createdAt || new Date()) },
        { label: 'User ID', value: user._id },
      ]),
      actionLabel: 'Open admin users',
      actionUrl: appLink('/admin/users'),
      footerNote: 'This notification contains account metadata for authorised management use only.',
      metadata: { userId: user._id, email: user.email },
    });
  }

  async function notifyOwnerAdminSignup(user) {
    if (!ADMIN_NOTIFICATION_EMAIL) return { skipped: true, reason: 'admin-notification-email-not-configured' };
    return sendBrandedEmail({
      recipientEmail: ADMIN_NOTIFICATION_EMAIL,
      bypassPreferences: true,
      eventType: 'operations.admin-signup',
      dedupeKey: `operations-admin-signup:${user._id}`,
      subject: `New administrator created: ${user.fullName}`,
      eyebrow: 'Security notification',
      title: 'A new Supreme administrator account was created',
      intro: 'Review this event immediately. If it was not authorised, suspend the account, rotate the administrator setup key and investigate the audit log.',
      content: detailRows([
        { label: 'Administrator', value: user.fullName },
        { label: 'Email', value: user.email },
        { label: 'Created', value: formatDateTime(user.createdAt || new Date()) },
        { label: 'User ID', value: user._id },
      ]),
      actionLabel: 'Open admin console',
      actionUrl: appLink('/admin'),
      footerNote: 'Administrator account creation is a security-sensitive event.',
      metadata: { userId: user._id, email: user.email },
    });
  }

  async function notifyOwnerPayment(transaction, user) {
    if (!ADMIN_NOTIFICATION_EMAIL || transaction.status !== 'completed') return { skipped: true };
    if (!['subscription', 'entry-fee', 'deposit'].includes(transaction.type)) return { skipped: true, reason: 'not-customer-payment' };
    return sendBrandedEmail({
      recipientEmail: ADMIN_NOTIFICATION_EMAIL,
      bypassPreferences: true,
      eventType: 'operations.payment-completed',
      dedupeKey: `operations-payment-completed:${transaction.reference}`,
      subject: `Payment received: ${formatUsd(transaction.amountCents)} from ${user.fullName}`,
      eyebrow: 'Completed customer payment',
      title: 'A payment has been confirmed',
      intro: `${user.fullName} completed a ${transaction.type === 'entry-fee' ? 'league entry' : transaction.type} payment.`,
      content: detailRows([
        { label: 'Customer', value: user.fullName },
        { label: 'Email', value: user.email },
        { label: 'Amount', value: formatUsd(transaction.amountCents) },
        { label: 'Purpose', value: transaction.description },
        { label: 'Method', value: transaction.metadata?.method || transaction.provider },
        { label: 'Reference', value: transaction.reference },
        { label: 'Confirmed', value: formatDateTime(transaction.updatedAt || new Date()) },
      ]),
      actionLabel: 'Review finances',
      actionUrl: appLink('/admin/finances'),
      footerNote: 'This is an internal operational notification. Verify the authoritative transaction and wallet records in the admin console.',
      metadata: { transactionId: transaction._id, userId: user._id, reference: transaction.reference },
    });
  }

  function paymentActionPath(transaction) {
    if (transaction.type === 'subscription') return '/app/subscription';
    if (transaction.type === 'entry-fee' && transaction.leagueId) return `/app/leagues/${transaction.leagueId}`;
    return '/app/wallet';
  }

  async function notifyPaymentUpdate(transaction) {
    if (!transaction) return null;
    const user = await User.findById(transaction.userId).lean();
    if (!user) return null;
    const description = String(transaction.description || 'Supreme payment');
    const providerStatus = String(transaction.metadata?.paynowStatus || transaction.status || '').trim();
    const normalizedProviderStatus = normalizePaynowStatus(providerStatus) || transaction.status;
    const state = transaction.status === 'completed'
      ? 'success'
      : transaction.status === 'reversed'
        ? 'reversed'
        : ['rejected', 'cancelled', 'failed'].includes(transaction.status)
          ? 'failed'
          : 'processing';
    const copy = {
      success: {
        subject: `Confirmed: ${description} — ${formatUsd(transaction.amountCents)}`,
        eyebrow: 'Payment confirmed',
        title: 'Your payment is confirmed',
        intro: `We confirmed ${description.toLowerCase()}. Your account and wallet records have been updated.`,
        actionLabel: transaction.type === 'entry-fee' ? 'View your league' : transaction.type === 'subscription' ? 'View subscription' : 'View wallet',
      },
      failed: {
        subject: 'Payment not completed — here is what to do next',
        eyebrow: 'Payment update',
        title: 'Your payment was not completed',
        intro: `The payment for ${description.toLowerCase()} did not complete. No successful charge has been recorded by Supreme Fantasy League.`,
        actionLabel: 'Review and try again',
      },
      reversed: {
        subject: `Important: ${description} was reversed`,
        eyebrow: 'Payment reversed',
        title: 'Your payment status changed',
        intro: `The payment for ${description.toLowerCase()} was reversed or refunded. Your wallet, subscription or league entry has been updated accordingly.`,
        actionLabel: 'Review transaction',
      },
      processing: {
        subject: `Action needed: complete ${description}`,
        eyebrow: 'Payment in progress',
        title: 'Complete your payment to unlock access',
        intro: `We created your payment request for ${description.toLowerCase()}. Follow only the instructions shown in the official checkout and keep the reference below.`,
        actionLabel: 'Check payment status',
      },
    }[state];

    const customerNotification = await sendBrandedEmail({
      user,
      eventType: `payment.${state}`,
      dedupeKey: `payment:${transaction.reference}:${transaction.status}:${normalizedProviderStatus}`,
      subject: copy.subject,
      eyebrow: copy.eyebrow,
      title: copy.title,
      intro: copy.intro,
      content: detailRows([
        { label: 'Amount', value: formatUsd(transaction.amountCents) },
        { label: 'Reference', value: transaction.reference },
        { label: 'Purpose', value: description },
        { label: 'Provider status', value: providerStatus || transaction.status },
        { label: 'Payment method', value: transaction.metadata?.method || transaction.provider },
        { label: 'Updated', value: formatDateTime(transaction.updatedAt || new Date()) },
      ]),
      actionLabel: copy.actionLabel,
      actionUrl: appLink(paymentActionPath(transaction)),
      footerNote: 'Do not approve an unexpected payment prompt. Supreme will never ask by SMS, WhatsApp, email or telephone for an OTP, password, PIN, CVC or a direct transfer of funds. Contact support inside the app if you did not initiate this payment.',
      metadata: { transactionId: transaction._id, reference: transaction.reference, status: transaction.status },
    });

    if (state === 'success') await notifyOwnerPayment(transaction, user);
    return customerNotification;
  }

  async function notifyAdminWalletAdjustment(transaction) {
    if (!transaction) return null;
    const user = await User.findById(transaction.userId).lean();
    if (!user) return null;
    const isRefund = transaction.type === 'refund';
    const reasonNote = String(transaction.metadata?.reason || '').trim() || transaction.description;

    return sendBrandedEmail({
      user,
      eventType: isRefund ? 'wallet.admin-refund' : 'wallet.admin-credit',
      dedupeKey: `wallet-adjustment:${transaction.reference}`,
      subject: isRefund
        ? `You've been refunded ${formatUsd(transaction.amountCents)} to your Supreme wallet`
        : `Your Supreme wallet was credited ${formatUsd(transaction.amountCents)}`,
      eyebrow: isRefund ? 'Refund issued' : 'Wallet credit',
      title: isRefund ? 'Your subscription was cancelled and refunded' : 'Your wallet balance was adjusted',
      intro: isRefund
        ? `An administrator cancelled your subscription and credited ${formatUsd(transaction.amountCents)} back to your Supreme wallet.`
        : `An administrator credited ${formatUsd(transaction.amountCents)} to your Supreme wallet.`,
      content: detailRows([
        { label: 'Amount credited', value: formatUsd(transaction.amountCents) },
        { label: 'Reason', value: reasonNote },
        { label: 'Reference', value: transaction.reference },
        { label: 'Date', value: formatDateTime(transaction.updatedAt || transaction.createdAt || new Date()) },
      ]),
      actionLabel: 'View wallet',
      actionUrl: appLink('/app/wallet'),
      footerNote: 'This adjustment was made by a Supreme Fantasy League administrator. Contact support inside the app if anything here looks unexpected.',
      metadata: { transactionId: transaction._id, reference: transaction.reference },
    });
  }

  async function notifyPerformanceBonus(transaction) {
    if (!transaction) return null;
    const user = await User.findById(transaction.userId).lean();
    if (!user) return null;
    const reason = String(transaction.metadata?.reason || transaction.description || 'Performance bonus').trim();
    return sendBrandedEmail({
      user,
      eventType: 'wallet.performance-bonus',
      dedupeKey: `performance-bonus:${transaction.reference}`,
      subject: `Performance bonus awarded — ${formatUsd(transaction.amountCents)}`,
      eyebrow: 'Performance reward',
      title: 'You earned a Supreme performance bonus',
      intro: `${formatUsd(transaction.amountCents)} has been credited to your Supreme wallet as a performance bonus. The credited amount is available for withdrawal subject to the normal withdrawal rules.`,
      content: detailRows([
        { label: 'Bonus', value: formatUsd(transaction.amountCents) },
        { label: 'Reason', value: reason },
        { label: 'Reference', value: transaction.reference },
        { label: 'Awarded', value: formatDateTime(transaction.updatedAt || transaction.createdAt || new Date()) },
      ]),
      actionLabel: 'View wallet / withdraw',
      actionUrl: appLink('/app/wallet'),
      footerNote: 'This reward was issued by Supreme Fantasy League. You can submit a withdrawal request from your wallet when your available balance meets the withdrawal requirements.',
      metadata: { transactionId: transaction._id, reference: transaction.reference, purpose: 'performance-bonus' },
    });
  }

  async function notifyLeagueCreated(user, league) {
    return sendBrandedEmail({
      user,
      eventType: 'league.created',
      dedupeKey: `league-created:${league._id}:${user._id}`,
      subject: `Your league is ready to go live — ${league.name}`,
      eyebrow: 'League draft created',
      title: 'Your league is ready for checkout',
      intro: `You created ${league.name}. Complete your entry payment to activate it, then share the unique code with the people you want to invite.`,
      content: detailRows([
        { label: 'League code', value: league.inviteCode },
        { label: 'Entry fee', value: formatUsd(league.entryFeeCents) },
        { label: 'Gameweeks', value: `${league.startGameweek}–${league.endGameweek}` },
        { label: 'Maximum members', value: league.maximumParticipants },
        { label: 'Expires', value: formatDateTime(league.expiresAt) },
      ]),
      actionLabel: 'Complete league checkout',
      actionUrl: appLink(`/app/leagues/${league._id}`),
      footerNote: 'The league code reserves access, but every member must complete their own entry payment.',
      category: 'league',
      metadata: { leagueId: league._id },
    });
  }

  async function notifyLeagueMembership(userId, leagueId, source = 'payment') {
    const [user, league] = await Promise.all([User.findById(userId).lean(), League.findById(leagueId).lean()]);
    if (!user || !league) return null;

    const result = await sendBrandedEmail({
      user,
      eventType: 'league.joined',
      dedupeKey: `league-joined:${league._id}:${user._id}`,
      subject: `You’re in: ${league.name}`,
      eyebrow: 'League entry confirmed',
      title: 'You are in the competition',
      intro: `Your place in ${league.name} is confirmed. Keep your FPL team current and return to the league page to follow the standings.`,
      content: detailRows([
        { label: 'League code', value: league.inviteCode || 'Public league' },
        { label: 'Entry fee', value: formatUsd(league.entryFeeCents) },
        { label: 'Gameweeks', value: `${league.startGameweek}–${league.endGameweek}` },
        { label: 'Entry source', value: source },
      ]),
      actionLabel: 'View league standings',
      actionUrl: appLink(`/app/leagues/${league._id}`),
      footerNote: 'Your linked FPL manager ID is used to calculate your qualifying gameweek points.',
      category: 'league',
      metadata: { leagueId: league._id },
    });

    if (league.createdBy && String(league.createdBy) !== String(user._id)) {
      const creator = await User.findById(league.createdBy).lean();
      if (creator) {
        await sendBrandedEmail({
          user: creator,
          eventType: 'league.member-joined',
          dedupeKey: `league-member-joined:${league._id}:${user._id}`,
          subject: `${user.fullName} just joined ${league.name}`,
          eyebrow: 'League activity',
          title: `${user.fullName} joined your league`,
          intro: `A new paid member has joined ${league.name}. You can view the updated member list and standings from the league page.`,
          content: detailRows([
            { label: 'Member', value: user.fullName },
            { label: 'League', value: league.name },
            { label: 'Joined', value: formatDateTime(new Date()) },
          ]),
          actionLabel: 'View league members',
          actionUrl: appLink(`/app/leagues/${league._id}`),
          category: 'league',
          metadata: { leagueId: league._id, joinedUserId: user._id },
        });
      }
    }
    return result;
  }

  async function notifyLeagueOutcomes(leagueId) {
    const league = await League.findById(leagueId).lean();
    if (!league || league.status !== 'settled') return { notified: 0 };
    const entries = await LeagueEntry.find({ leagueId, paymentStatus: 'paid' })
      .sort({ currentRank: 1, currentScore: -1, latestOverallRank: 1, joinedAt: 1 })
      .lean();
    if (!entries.length) return { notified: 0 };

    const users = await User.find({ _id: { $in: entries.map((entry) => entry.userId) } }).lean();
    const userMap = new Map(users.map((user) => [String(user._id), user]));
    const explicitWinners = entries.filter((entry) => Number(entry.prizeCents || 0) > 0);
    const winnerIds = new Set((explicitWinners.length ? explicitWinners : entries.filter((entry) => Number(entry.currentRank || 0) === 1))
      .map((entry) => String(entry.userId)));

    let notified = 0;
    for (const entry of entries) {
      const user = userMap.get(String(entry.userId));
      if (!user) continue;
      const won = winnerIds.has(String(entry.userId));
      await sendBrandedEmail({
        user,
        eventType: won ? 'league.won' : 'league.lost',
        dedupeKey: `league-outcome:${league._id}:${entry.userId}:${entry.currentRank}:${entry.prizeCents || 0}`,
        subject: won ? `You finished on top — ${league.name}` : `Final standings are in — ${league.name}`,
        eyebrow: won ? 'Competition winner' : 'Competition complete',
        title: won ? 'You finished on top' : 'The final standings are ready',
        intro: won
          ? `Congratulations — you won ${league.name}. Your final position and any recorded prize are shown below.`
          : `Thank you for competing in ${league.name}. You did not take the winning position this time, but your final result is now available.`,
        content: detailRows([
          { label: 'Final rank', value: `#${entry.currentRank || '—'}` },
          { label: 'Final score', value: entry.currentScore },
          { label: 'Prize', value: formatUsd(entry.prizeCents || 0) },
          { label: 'Scored through', value: league.scoreThroughGameweek ? `Gameweek ${league.scoreThroughGameweek}` : 'Final review' },
        ]),
        actionLabel: 'View final standings',
        actionUrl: appLink(`/app/leagues/${league._id}`),
        footerNote: won ? 'Prize availability follows the recorded settlement and payout status shown in your wallet.' : 'You can review past competitions at any time from My Leagues.',
        category: 'result',
        metadata: { leagueId: league._id, rank: entry.currentRank, prizeCents: entry.prizeCents || 0 },
      });
      notified += 1;
    }
    return { notified };
  }

  async function sendStaleTeamReminders() {
    if (!EMAILS_ENABLED) return { checked: 0, sent: 0 };
    const threshold = new Date(Date.now() - TEAM_INACTIVITY_DAYS * 24 * 60 * 60 * 1000);
    const cooldownThreshold = new Date(Date.now() - TEAM_REMINDER_COOLDOWN_DAYS * 24 * 60 * 60 * 1000);
    const users = await User.find({
      role: 'user',
      status: 'active',
      fplManagerId: { $type: 'string', $ne: '' },
    }).select('fullName email fplManagerId createdAt').lean();
    if (!users.length) return { checked: 0, sent: 0 };

    const latestSnapshots = await TeamSnapshot.aggregate([
      { $match: { userId: { $in: users.map((user) => user._id) } } },
      { $sort: { lastSuccessfulSyncAt: -1, fetchedAt: -1, createdAt: -1 } },
      { $group: { _id: '$userId', lastSyncAt: { $first: '$lastSuccessfulSyncAt' }, fetchedAt: { $first: '$fetchedAt' } } },
    ]);
    const snapshotMap = new Map(latestSnapshots.map((snapshot) => [String(snapshot._id), snapshot.lastSyncAt || snapshot.fetchedAt]));

    let sent = 0;
    for (const user of users) {
      const lastUpdatedAt = snapshotMap.get(String(user._id)) || user.createdAt;
      if (!lastUpdatedAt || new Date(lastUpdatedAt) > threshold) continue;
      const recent = await EmailNotification.exists({
        userId: user._id,
        eventType: 'team.inactive',
        status: 'sent',
        sentAt: { $gte: cooldownThreshold },
      });
      if (recent) continue;

      const notification = await sendBrandedEmail({
        user,
        eventType: 'team.inactive',
        dedupeKey: `team-inactive:${user._id}:${new Date().toISOString().slice(0, 10)}`,
        subject: 'Your next competition starts with a fresh team',
        eyebrow: 'Team reminder',
        title: 'We have not refreshed your team in two weeks',
        intro: `Your linked FPL team has not been synchronised with Supreme Fantasy League for at least ${TEAM_INACTIVITY_DAYS} days. Refresh it before your next competition so your team details are current.`,
        content: detailRows([
          { label: 'FPL manager ID', value: user.fplManagerId },
          { label: 'Last successful refresh', value: formatDateTime(lastUpdatedAt) },
          { label: 'Reminder threshold', value: `${TEAM_INACTIVITY_DAYS} days` },
        ]),
        actionLabel: 'Refresh your fantasy team',
        actionUrl: appLink('/app/team'),
        footerNote: 'League scoring uses official FPL gameweek history, but keeping your linked team current helps prevent eligibility and account-linking issues.',
        category: 'team-reminder',
        metadata: { lastUpdatedAt, fplManagerId: user.fplManagerId },
      });
      if (notification?.status === 'sent') sent += 1;
    }
    return { checked: users.length, sent };
  }

  async function sendTestEmail(user) {
    return sendBrandedEmail({
      user,
      eventType: 'email.test',
      dedupeKey: `email-test:${user._id}:${Date.now()}`,
      subject: 'Supreme email delivery confirmed',
      eyebrow: 'Delivery confirmation',
      title: 'Your transactional email channel is working',
      intro: 'This confirms that Supreme Fantasy League can send branded transactional email through the configured sending domain.',
      content: detailRows([
        { label: 'Recipient', value: user.email },
        { label: 'Sender', value: SENDING_EMAIL },
        { label: 'Environment', value: process.env.NODE_ENV || 'application' },
        { label: 'Sent', value: formatDateTime(new Date()) },
      ]),
      actionLabel: 'Return to dashboard',
      actionUrl: appLink('/app/dashboard'),
    });
  }

  const safeNotification = (name, handler) => async (...args) => {
    try {
      return await handler(...args);
    } catch (error) {
      console.error(`Email workflow failed: ${name}`, error.message);
      return { status: 'failed', error: String(error.message || error) };
    }
  };

  return {
    enabled: EMAILS_ENABLED,
    reminderCheckIntervalMs: REMINDER_CHECK_INTERVAL_MS,
    EmailNotification,
    notifyWelcome: safeNotification('notifyWelcome', notifyWelcome),
    notifyAdminWelcome: safeNotification('notifyAdminWelcome', notifyAdminWelcome),
    notifyOwnerUserSignup: safeNotification('notifyOwnerUserSignup', notifyOwnerUserSignup),
    notifyOwnerAdminSignup: safeNotification('notifyOwnerAdminSignup', notifyOwnerAdminSignup),
    notifyPaymentUpdate: safeNotification('notifyPaymentUpdate', notifyPaymentUpdate),
    notifyAdminWalletAdjustment: safeNotification('notifyAdminWalletAdjustment', notifyAdminWalletAdjustment),
    notifyPerformanceBonus: safeNotification('notifyPerformanceBonus', notifyPerformanceBonus),
    notifyLeagueCreated: safeNotification('notifyLeagueCreated', notifyLeagueCreated),
    notifyLeagueMembership: safeNotification('notifyLeagueMembership', notifyLeagueMembership),
    notifyLeagueOutcomes: safeNotification('notifyLeagueOutcomes', notifyLeagueOutcomes),
    sendStaleTeamReminders: safeNotification('sendStaleTeamReminders', sendStaleTeamReminders),
    sendTestEmail: safeNotification('sendTestEmail', sendTestEmail),
  };
}

module.exports = { createLocalEmailService };
