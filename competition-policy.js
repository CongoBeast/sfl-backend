'use strict';

// Price of joining the competition (not the stored one-off fee). Monthly,
// half-season and season leagues require a paid subscription. They deliberately
// have zero one-off entry fee, which must never be presented as FREE entry.
const MINIMUM_PLAN_CENTS = Object.freeze({ monthly: 200, 'bi-weekly': 500, weekly: 2000, 'half-season': 2000, season: 4000 });

function isClashOfCaptains(meta, league) {
  return Boolean(
    league?.officialSupremeLeague &&
    league.competitionType === 'clash-captains' &&
    meta?.cadence === 'clash-captains' &&
    meta?.entryMode === 'free-all' &&
    meta?.scoringMode === 'captain-vice'
  );
}

function pricingForLeague(league, meta = null, planPrices = {}) {
  const clash = isClashOfCaptains(meta, league);
  if (clash) return { freeEntry: true, subscriptionOnly: false, oneOffAllowed: false, accessPriceCents: 0, oneOffEntryFeeCents: null, priceType: 'free', paymentOptions: ['free'] };

  const cadence = String(meta?.cadence || league?.cadence || league?.competitionType || '');
  const publishedFee = Number(league?.entryFeeCents || 0);
  // Do not trust accidentally corrupted `entryMode: free-all` for any other league.
  // A valid published weekly/bi-weekly fee is payable even if a legacy
  // metadata record incorrectly says 'free-all'. Strict free classification
  // above always wins only for an actual Clash competition.
  const oneOffAllowed = Number.isInteger(publishedFee) && publishedFee > 0 && (
    !league?.officialSupremeLeague || ['weekly', 'bi-weekly'].includes(cadence)
  );
  if (oneOffAllowed) {
    return { freeEntry: false, subscriptionOnly: false, oneOffAllowed: true, accessPriceCents: publishedFee,
      oneOffEntryFeeCents: publishedFee, priceType: 'one-off', paymentOptions: league?.officialSupremeLeague ? ['subscription', 'one-off'] : ['one-off'] };
  }
  if (league?.officialSupremeLeague) {
    const candidate = Number(planPrices[cadence] ?? MINIMUM_PLAN_CENTS[cadence]);
    const accessPriceCents = Number.isInteger(candidate) && candidate > 0 ? candidate : null;
    return { freeEntry: false, subscriptionOnly: true, oneOffAllowed: false, accessPriceCents,
      oneOffEntryFeeCents: null, priceType: 'subscription', paymentOptions: ['subscription'] };
  }
  // Unknown non-official zero-cost leagues need investigation, not a FREE label.
  return { freeEntry: false, subscriptionOnly: false, oneOffAllowed: false, accessPriceCents: null,
    oneOffEntryFeeCents: null, priceType: 'unavailable', paymentOptions: [] };
}

function compareClashEntries(a, b) {
  const scoreDiff = Number(b.currentScore || 0) - Number(a.currentScore || 0);
  if (scoreDiff) return scoreDiff;
  const overallDiff = Number(b.scoreDetails?.overallPoints || 0) - Number(a.scoreDetails?.overallPoints || 0);
  if (overallDiff) return overallDiff;
  // Unpublished tertiary tie-break, deterministic: stable entry ID order.
  return String(a._id).localeCompare(String(b._id));
}

module.exports = { isClashOfCaptains, pricingForLeague, compareClashEntries };
