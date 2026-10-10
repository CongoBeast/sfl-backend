'use strict';

// Paynow captures are the ONLY external receipts represented by transactions;
// a wallet-funded purchase or an internally credited prize is not new cash.
// Paynow subscriptions and league entries use a DEBIT transaction direction
// because they charge the user's purchase, while deposits use CREDIT.
const externalCashInMatch = () => ({
  status: 'completed',
  provider: 'paynow',
  'metadata.paynowTestMode': { $ne: true },
  $or: [
    { type: 'deposit', direction: 'credit' },
    { type: { $in: ['subscription', 'entry-fee'] }, direction: 'debit' },
  ],
});
const externalCashOutMatch = () => ({
  status: 'completed', type: 'withdrawal', direction: 'debit',
});

function completionDateStage(isPayout) {
  return { $addFields: { cashAt: isPayout
    ? { $ifNull: ['$metadata.paidAt', '$updatedAt'] }
    : { $ifNull: ['$metadata.finalizedAt', '$updatedAt'] } } };
}

async function cashAggregate(Transaction, match, isPayout, start = null, end = null) {
  const pipeline = [ { $match: match }, completionDateStage(isPayout) ];
  if (start || end) pipeline.push({ $match: { cashAt: {
    ...(start ? { $gte: start } : {}), ...(end ? { $lt: end } : {}),
  } } });
  pipeline.push({ $group: { _id: null, amountCents: { $sum: '$amountCents' }, count: { $sum: 1 } } });
  const [row] = await Transaction.aggregate(pipeline);
  return { amountCents: Number(row?.amountCents || 0), count: Number(row?.count || 0) };
}

async function getCashAccounting(Transaction, now = new Date()) {
  const monthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const previousStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  const periods = [ ['lifetime', null, null], ['thisMonth', monthStart, null], ['lastMonth', previousStart, monthStart] ];
  const outputs = await Promise.all(periods.map(async ([key, from, to]) => {
    const [received, paid] = await Promise.all([
      cashAggregate(Transaction, externalCashInMatch(), false, from, to),
      cashAggregate(Transaction, externalCashOutMatch(), true, from, to),
    ]);
    return [key, { collectedCents: received.amountCents, paidOutCents: paid.amountCents,
      netCashMovementCents: received.amountCents - paid.amountCents,
      collectionsCount: received.count, withdrawalsCount: paid.count }];
  }));
  return Object.fromEntries(outputs);
}
module.exports = { externalCashInMatch, externalCashOutMatch, getCashAccounting };
