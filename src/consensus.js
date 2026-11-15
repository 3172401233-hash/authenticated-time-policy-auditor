'use strict';

// Weighted-cluster consensus over time-source samples. The largest cluster
// whose spread fits inside toleranceMs wins; it must hold a strict majority
// of the total priority weight to be authoritative.
function computeConsensus(samples, toleranceMs) {
  if (!Array.isArray(samples) || samples.length === 0) {
    return { status: 'unavailable', timeMs: null, members: [], clusterWeight: 0, totalWeight: 0 };
  }
  const sorted = [...samples].sort((a, b) => a.timeMs - b.timeMs);
  const totalWeight = sorted.reduce((sum, s) => sum + s.priority, 0);

  let best = null;
  for (let i = 0; i < sorted.length; i += 1) {
    let weight = 0;
    let weightedSum = 0;
    const members = [];
    for (let j = i; j < sorted.length; j += 1) {
      if (sorted[j].timeMs - sorted[i].timeMs > toleranceMs) break;
      weight += sorted[j].priority;
      weightedSum += sorted[j].priority * sorted[j].timeMs;
      members.push(sorted[j].sourceId);
    }
    if (!best || weight > best.weight) {
      best = { weight, weightedSum, members };
    }
  }

  const timeMs = Math.round(best.weightedSum / best.weight);
  const majority = best.weight * 2 > totalWeight;
  return {
    status: majority ? 'ok' : 'conflict',
    timeMs,
    members: best.members,
    clusterWeight: best.weight,
    totalWeight,
  };
}

module.exports = { computeConsensus };
