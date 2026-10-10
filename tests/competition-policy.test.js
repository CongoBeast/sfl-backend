'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { isClashOfCaptains, pricingForLeague, compareClashEntries } = require('../competition-policy');
const { externalCashInMatch, externalCashOutMatch } = require('../cash-accounting');
const league = (type, fee = 0) => ({ officialSupremeLeague: true, competitionType: type, cadence: type, entryFeeCents: fee });
const meta = (type, mode = 'subscription', score = 'manager-points') => ({ cadence: type, entryMode: mode, scoringMode: score });
test('only real Clash of Captains is free', () => {
  assert.equal(isClashOfCaptains(meta('clash-captains', 'free-all', 'captain-vice'), league('clash-captains')), true);
  assert.equal(pricingForLeague(league('monthly'), meta('monthly', 'free-all')).freeEntry, false);
  assert.equal(pricingForLeague(league('monthly'), meta('monthly', 'free-all')).subscriptionOnly, true);
  assert.equal(pricingForLeague(league('clash-captains'), meta('clash-captains', 'free-all', 'manager-points')).freeEntry, false);
});
test('monthly $0 one-off fee cannot show free and displays real paid plan', () => {
  assert.deepEqual(pricingForLeague(league('monthly'), meta('monthly')).paymentOptions, ['subscription']);
  assert.equal(pricingForLeague(league('monthly'), meta('monthly'), {monthly: 200}).accessPriceCents, 200);
  assert.equal(pricingForLeague(league('weekly', 100), meta('weekly', 'weekly-flex')).accessPriceCents, 100);
  assert.equal(pricingForLeague(league('bi-weekly', 300), meta('bi-weekly', 'one-off-flex')).accessPriceCents, 300);
});
test('highest gameweek score followed by overall season points, then stable ID', () => {
  const entries = [
    { _id:'c', currentScore:11, scoreDetails: { overallPoints: 700 } },
    { _id:'b', currentScore:13, scoreDetails: { overallPoints: 650 } },
    { _id:'a', currentScore:13, scoreDetails: { overallPoints: 850 } },
  ];
  entries.sort(compareClashEntries);
  assert.deepEqual(entries.map((entry) => entry._id), ['a', 'b', 'c']);
  assert.equal(compareClashEntries({ _id:'a', currentScore:11, scoreDetails:{overallPoints:700} }, { _id:'b', currentScore:11, scoreDetails:{overallPoints:700} }) < 0, true);
});
test('real cash does not include mock, wallet spend or internal prize credits', () => {
  assert.equal(externalCashInMatch().provider, 'paynow');
  assert.equal(externalCashOutMatch().type, 'withdrawal');
});
test('corrupt free-all weekly stays payable at its published fee', () => {
  const wrong = pricingForLeague(league('weekly', 100), meta('weekly', 'free-all'));
  assert.equal(wrong.freeEntry, false);
  assert.equal(wrong.oneOffAllowed, true);
  assert.equal(wrong.accessPriceCents, 100);
});

test('paynow purchase debits count as external cash collected, but mock, wallet and test charges do not', async () => {
  const { getCashAccounting } = require('../cash-accounting');
  const transactions = [
    { status: 'completed', type: 'deposit', provider: 'paynow', direction: 'credit', amountCents: 1000, metadata: { finalizedAt: new Date('2026-09-08T08:00:00Z') } },
    { status: 'completed', type: 'subscription', provider: 'paynow', direction: 'debit', amountCents: 200, metadata: { finalizedAt: new Date('2026-09-20T08:00:00Z') } },
    { status: 'completed', type: 'entry-fee', provider: 'paynow', direction: 'debit', amountCents: 300, metadata: { finalizedAt: new Date('2026-10-03T08:00:00Z'), paynowTestMode: false } },
    { status: 'completed', type: 'entry-fee', provider: 'paynow', direction: 'debit', amountCents: 500, metadata: { finalizedAt: new Date('2026-10-03T08:00:00Z'), paynowTestMode: true } },
    { status: 'completed', type: 'subscription', provider: 'mock', direction: 'debit', amountCents: 900, metadata: { finalizedAt: new Date('2026-10-03T08:00:00Z') } },
    { status: 'completed', type: 'subscription', provider: 'wallet', direction: 'debit', amountCents: 200, metadata: { finalizedAt: new Date('2026-10-04T08:00:00Z') } },
    { status: 'completed', type: 'prize', provider: 'admin-settlement', direction: 'credit', amountCents: 400, metadata: { finalizedAt: new Date('2026-10-05T08:00:00Z') } },
    { status: 'completed', type: 'deposit', provider: 'paynow', direction: 'credit', amountCents: 700, metadata: { finalizedAt: new Date('2025-06-02T08:00:00Z') } },
    { status: 'completed', type: 'withdrawal', provider: 'wallet', direction: 'debit', amountCents: 500, metadata: { paidAt: new Date('2026-10-06T08:00:00Z') } },
    { status: 'pending', type: 'withdrawal', provider: 'wallet', direction: 'debit', amountCents: 600, metadata: { paidAt: new Date('2026-10-06T08:00:00Z') } },
  ];
  const field = (object, key) => key.split('.').reduce((value, component) => value?.[component], object);
  const matches = (row, clause) => Object.entries(clause).every(([key, wanted]) => {
    if (key === '$or') return wanted.some((sub) => matches(row, sub));
    const actual = field(row, key);
    if (wanted && typeof wanted === 'object' && !(wanted instanceof Date)) return Object.entries(wanted).every(([op, value]) => {
      if (op === '$ne') return actual !== value;
      if (op === '$in') return value.includes(actual);
      if (op === '$gte') return actual >= value;
      if (op === '$lt') return actual < value;
      throw new Error(`Unrecognized Mongo operator in test: ${op}`);
    });
    return actual === wanted;
  });
  const fakeTransaction = {
    async aggregate(pipeline) {
      let rows = transactions;
      for (const stage of pipeline) {
        if (stage.$match) rows = rows.filter((row) => matches(row, stage.$match));
        if (stage.$addFields?.cashAt) {
          const expr = stage.$addFields.cashAt.$ifNull;
          rows = rows.map((row) => ({ ...row, cashAt: field(row, expr[0].slice(1)) || field(row, expr[1].slice(1)) }));
        }
        if (stage.$group) return rows.length ? [{ amountCents: rows.reduce((sum, row) => sum + row.amountCents, 0), count: rows.length }] : [];
      }
      return rows;
    },
  };
  const cash = await getCashAccounting(fakeTransaction, new Date('2026-10-10T12:00:00Z'));
  assert.equal(cash.lifetime.collectedCents, 2200);
  assert.equal(cash.thisMonth.collectedCents, 300);
  assert.equal(cash.lastMonth.collectedCents, 1200);
  assert.equal(cash.lifetime.paidOutCents, 500);
  assert.equal(cash.thisMonth.paidOutCents, 500);
  assert.equal(cash.lastMonth.paidOutCents, 0);
  assert.equal(cash.thisMonth.netCashMovementCents, -200);
});

test('unknown paid-policy metadata does not create a free-entry loophole', () => {
  const ambiguous = pricingForLeague({ officialSupremeLeague: true, competitionType: 'monthly', cadence: 'monthly', entryFeeCents: 0 }, null, { monthly: 0 });
  assert.equal(ambiguous.freeEntry, false);
  assert.equal(ambiguous.subscriptionOnly, true);
  assert.equal(ambiguous.accessPriceCents, null);
  assert.deepEqual(ambiguous.paymentOptions, ['subscription']);
});
