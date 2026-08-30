#!/usr/bin/env node
'use strict';

const mongoose = require('mongoose');
const app = require('../server');

const FPL_BASE_URL = String(process.env.FPL_BASE_URL || 'https://fantasy.premierleague.com/api').replace(/\/$/, '');
const WEEKLY_ENTRY_FEE_CENTS = Number.parseInt(process.env.SUPREME_WEEKLY_ENTRY_FEE_CENTS || '100', 10);
const WEEKLY_PRIZE_CENTS = Number.parseInt(process.env.SUPREME_WEEKLY_PRIZE_CENTS || '1000', 10);
const CLASH_PRIZE_CENTS = Number.parseInt(process.env.SUPREME_CLASH_CAPTAINS_PRIZE_CENTS || '300', 10);
const REQUEST_TIMEOUT_MS = Math.max(3000, Math.min(30000, Number(process.env.FPL_REQUEST_TIMEOUT_MS || 12000)));
const DRY_RUN = process.argv.includes('--dry-run');

async function fetchFplJson(resource) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(`${FPL_BASE_URL}${resource}`, {
      headers: { Accept: 'application/json', 'User-Agent': 'SupremeFantasyLeague/league-time-correction' },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`FPL returned HTTP ${response.status} for ${resource}`);
    return response.json();
  } finally {
    clearTimeout(timeout);
  }
}

function eventMap(bootstrap) {
  return new Map((bootstrap.events || []).map((event) => [Number(event.id), event]));
}

function validDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function lastFixtureKickoff(fixtures) {
  return (fixtures || [])
    .map((fixture) => validDate(fixture.kickoff_time))
    .filter(Boolean)
    .sort((a, b) => b.getTime() - a.getTime())[0] || null;
}

async function main() {
  if (String(process.env.FPL_DATA_MODE || '').trim().toLowerCase() !== 'public') {
    throw new Error('Set FPL_DATA_MODE=public before running this correction. The script refuses to guess gameweek dates.');
  }

  await app.connectDatabase();

  const League = mongoose.model('League');
  const LeagueEntry = mongoose.model('LeagueEntry');
  const LeagueAccessPolicy = mongoose.model('LeagueAccessPolicy');
  const SupremeLeagueMeta = mongoose.model('SupremeLeagueMeta');

  const bootstrap = await fetchFplJson('/bootstrap-static/');
  const events = eventMap(bootstrap);
  if (!events.size) throw new Error('FPL bootstrap-static returned no gameweek events. Nothing was changed.');

  const leagues = await League.find({ status: { $nin: ['settled', 'cancelled'] } }).sort({ createdAt: 1 });
  const usedGameweeks = [...new Set(leagues.flatMap((league) => {
    const start = Number(league.startGameweek);
    const end = Number(league.endGameweek);
    return Number.isInteger(start) && Number.isInteger(end) ? Array.from({ length: Math.max(0, end - start + 1) }, (_, index) => start + index) : [];
  }).filter((gw) => events.has(gw)))];
  const fixtureState = new Map();

  for (const gw of usedGameweeks) {
    const fixtures = await fetchFplJson(`/fixtures/?event=${gw}`);
    fixtureState.set(gw, {
      lastKickoffAt: lastFixtureKickoff(fixtures),
      fixtureCount: Array.isArray(fixtures) ? fixtures.length : 0,
      allFinished: Array.isArray(fixtures) && fixtures.length > 0 && fixtures.every((fixture) => fixture.finished === true),
    });
  }

  const now = new Date();
  const staleLockBefore = new Date(now.getTime() - 15 * 60 * 1000);
  const summary = {
    dryRun: DRY_RUN,
    checked: leagues.length,
    updatedLeagues: 0,
    updatedPolicies: 0,
    updatedSupremeMeta: 0,
    clearedGuessedExpiries: 0,
    markedFootballFinished: 0,
    awaitingDataCheck: 0,
    weeklyPriceCorrections: 0,
    clashPrizeCorrections: 0,
    resetStaleSettlementLocks: 0,
    skippedMissingFplEvent: 0,
  };

  for (const league of leagues) {
    const startEvent = events.get(Number(league.startGameweek));
    const endEvent = events.get(Number(league.endGameweek));
    if (!startEvent || !endEvent) {
      summary.skippedMissingFplEvent += 1;
      continue;
    }

    const startDeadlineAt = validDate(startEvent.deadline_time);
    const lastKickoffAt = fixtureState.get(Number(league.endGameweek))?.lastKickoffAt || null;
    const rangeEvents = [];
    for (let gw = Number(league.startGameweek); gw <= Number(league.endGameweek); gw += 1) {
      if (events.has(gw)) rangeEvents.push(events.get(gw));
    }
    const footballFinished = rangeEvents.length === Number(league.endGameweek) - Number(league.startGameweek) + 1
      && rangeEvents.every((event) => event.finished === true && fixtureState.get(Number(event.id))?.allFinished === true);
    const scoringFinalized = footballFinished && rangeEvents.every((event) => event.data_checked === true);
    const paidCount = await LeagueEntry.countDocuments({ leagueId: league._id, paymentStatus: 'paid' });

    league.fplJoinDeadlineAt = startDeadlineAt;
    league.fplLastFixtureKickoffAt = lastKickoffAt;

    if (footballFinished) {
      const observedFinishedAt = league.fplFinishedAt || now;
      league.fplFinishedAt = observedFinishedAt;
      league.expiresAt = observedFinishedAt;
      league.completedAt = league.completedAt || observedFinishedAt;
      if (['open', 'full', 'upcoming', 'live'].includes(league.status)) league.status = 'awaiting-review';
      summary.markedFootballFinished += 1;
    } else {
      if (league.expiresAt) summary.clearedGuessedExpiries += 1;
      league.expiresAt = null;
      league.fplFinishedAt = null;
      league.completedAt = null;
      if (league.status === 'awaiting-review') {
        if (paidCount >= Number(league.maximumParticipants || Infinity)) league.status = 'full';
        else if (startDeadlineAt && now >= startDeadlineAt) league.status = 'live';
        else league.status = 'open';
      }
    }

    if (scoringFinalized) {
      league.fplDataCheckedAt = league.fplDataCheckedAt || now;
    } else {
      league.fplDataCheckedAt = null;
      if (footballFinished) summary.awaitingDataCheck += 1;
    }

    const meta = await SupremeLeagueMeta.findOne({ leagueId: league._id });
    if (meta) {
      meta.joinDeadlineAt = startDeadlineAt || meta.joinDeadlineAt;
      meta.lastFixtureKickoffAt = lastKickoffAt;
      if (footballFinished) meta.finishedAt = meta.finishedAt || now;
      else meta.finishedAt = null;
      if (scoringFinalized) meta.dataCheckedAt = meta.dataCheckedAt || now;
      else meta.dataCheckedAt = null;

      if (meta.cadence === 'weekly') {
        league.entryFeeCents = WEEKLY_ENTRY_FEE_CENTS;
        league.projectedPrizeCents = WEEKLY_PRIZE_CENTS;
        league.displayedPrizeCents = WEEKLY_PRIZE_CENTS;
        league.guaranteedPrize = true;
        meta.entryFeeCents = WEEKLY_ENTRY_FEE_CENTS;
        meta.prizeCents = WEEKLY_PRIZE_CENTS;
        meta.entryMode = 'weekly-flex';
        meta.scoringMode = 'manager-points';
        summary.weeklyPriceCorrections += 1;
      }

      if (meta.cadence === 'clash-captains') {
        league.entryFeeCents = 0;
        league.projectedPrizeCents = CLASH_PRIZE_CENTS;
        league.displayedPrizeCents = CLASH_PRIZE_CENTS;
        league.guaranteedPrize = true;
        meta.entryFeeCents = 0;
        meta.prizeCents = CLASH_PRIZE_CENTS;
        meta.entryMode = 'free-all';
        meta.scoringMode = 'captain-vice';
        summary.clashPrizeCorrections += 1;
      }

      const lockIsStale = meta.settlementStatus === 'scoring'
        && (!meta.settlementLockedAt || new Date(meta.settlementLockedAt) <= staleLockBefore);
      if (lockIsStale) {
        meta.settlementStatus = 'open';
        meta.settlementLockId = '';
        meta.settlementLockedAt = null;
        summary.resetStaleSettlementLocks += 1;
      }

      if (!DRY_RUN) await meta.save();
      summary.updatedSupremeMeta += 1;
    }

    const policy = await LeagueAccessPolicy.findOne({ leagueId: league._id });
    if (policy && startDeadlineAt) {
      const currentDeadline = validDate(policy.joinDeadlineAt);
      if (league.officialSupremeLeague || !currentDeadline || currentDeadline > startDeadlineAt) {
        policy.joinDeadlineAt = startDeadlineAt;
        policy.allowLateJoin = false;
        if (!DRY_RUN) await policy.save();
        summary.updatedPolicies += 1;
      }
    }

    if (!DRY_RUN) await league.save();
    summary.updatedLeagues += 1;
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(DRY_RUN
    ? 'Dry run complete. Re-run without --dry-run to apply the corrections.'
    : 'League timing correction complete. Run the normal maintenance endpoint/job next so data_checked leagues can settle.');
}

main()
  .catch((error) => {
    console.error(error.stack || error.message || error);
    process.exitCode = 1;
  })
  .finally(async () => {
    try { await mongoose.disconnect(); } catch { /* no-op */ }
  });
