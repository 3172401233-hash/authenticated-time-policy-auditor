'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { computeConsensus } = require('../index.js');

test('majority cluster wins over an outlier source', () => {
  const result = computeConsensus(
    [
      { sourceId: 'a', priority: 1, timeMs: 10_000 },
      { sourceId: 'b', priority: 1, timeMs: 10_400 },
      { sourceId: 'c', priority: 1, timeMs: 40_000 },
    ],
    2_000
  );
  assert.equal(result.status, 'ok');
  assert.equal(result.timeMs, 10_200);
  assert.deepEqual(result.members.sort(), ['a', 'b']);
});

test('conflicting sources without a majority cluster report conflict', () => {
  const result = computeConsensus(
    [
      { sourceId: 'a', priority: 1, timeMs: 0 },
      { sourceId: 'b', priority: 1, timeMs: 5_000 },
      { sourceId: 'c', priority: 1, timeMs: 10_000 },
    ],
    1_000
  );
  assert.equal(result.status, 'conflict');
});

test('priority weight decides between competing pairs', () => {
  const result = computeConsensus(
    [
      { sourceId: 'low-a', priority: 1, timeMs: 0 },
      { sourceId: 'low-b', priority: 1, timeMs: 500 },
      { sourceId: 'high-a', priority: 3, timeMs: 8_000 },
      { sourceId: 'high-b', priority: 1, timeMs: 8_400 },
    ],
    1_000
  );
  assert.equal(result.status, 'ok');
  assert.ok(result.members.includes('high-a'));
  assert.equal(result.timeMs, 8_100);
});

test('empty sample set is unavailable', () => {
  assert.equal(computeConsensus([], 1_000).status, 'unavailable');
});
