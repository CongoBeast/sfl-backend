#!/usr/bin/env node
'use strict';

const mongoose = require('mongoose');
const app = require('../server');

async function main() {
  if (String(process.env.FPL_DATA_MODE || '').trim().toLowerCase() !== 'public') {
    throw new Error('Set FPL_DATA_MODE=public in the backend .env before running competition maintenance.');
  }

  console.log('Running Supreme competition maintenance against the configured database...');
  const result = await app.runGrowthMaintenance();
  console.log(JSON.stringify(result, null, 2));
  console.log('Competition maintenance complete. Future leagues were reconciled from the live FPL schedule, eligible users were enrolled, and ready leagues were offered for settlement.');
}

main()
  .catch((error) => {
    console.error(error.stack || error.message || error);
    process.exitCode = 1;
  })
  .finally(async () => {
    try { await mongoose.disconnect(); } catch { /* no-op */ }
  });
