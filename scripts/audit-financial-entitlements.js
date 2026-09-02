#!/usr/bin/env node
'use strict';

const mongoose = require('mongoose');
const app = require('../server');

async function main() {
  const apply = process.argv.includes('--apply');
  console.log(apply
    ? 'Applying subscription/payment entitlement audit...'
    : 'Previewing subscription/payment entitlement audit (no database changes)...');

  const result = await app.auditFinancialEntitlements({ apply });
  console.log(JSON.stringify(result, null, 2));

  if (!apply && (result.invalidSubscriptions?.length || result.invalidEntries?.length)) {
    console.log('\nProblems were found. Review the output, then run:');
    console.log('node scripts/audit-financial-entitlements.js --apply');
  } else if (apply) {
    console.log('\nAudit applied. Invalid active subscriptions were disabled and unsupported subscription league entries were removed.');
  }
}

main()
  .catch((error) => {
    console.error(error.stack || error.message || error);
    process.exitCode = 1;
  })
  .finally(async () => {
    try { await mongoose.disconnect(); } catch { /* no-op */ }
  });
