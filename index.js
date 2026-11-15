'use strict';

const { TimePolicyAuditor, DEFAULTS } = require('./src/auditor.js');
const { Keyring } = require('./src/keyring.js');
const { computeConsensus } = require('./src/consensus.js');
const { ReplayWindow } = require('./src/replay-window.js');
const statements = require('./src/statements.js');

module.exports = {
  TimePolicyAuditor,
  DEFAULTS,
  Keyring,
  computeConsensus,
  ReplayWindow,
  ...statements,
};
