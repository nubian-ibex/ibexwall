import type { CheckResult, Posture } from '../gen/contracts';

/** What the overview headline says. Calm by design: never red. */
export type Overall = 'unknown' | 'protected' | 'attention';

const HIGH = new Set(['high', 'critical']);

export function overallStatus(posture: Posture): Overall {
  if (posture.score == null) return 'unknown';
  const results = posture.results ?? [];
  const seriousFailure = results.some((r) => r.outcome === 'fail' && HIGH.has(r.severity));
  return posture.score >= 90 && !seriousFailure ? 'protected' : 'attention';
}

export function counts(results: CheckResult[]) {
  const assessed = results.filter((r) => r.outcome === 'pass' || r.outcome === 'fail');
  return {
    assessed: assessed.length,
    passed: assessed.filter((r) => r.outcome === 'pass').length,
    failed: assessed.filter((r) => r.outcome === 'fail').length,
    notAssessed: results.filter((r) => r.outcome === 'not_assessed').length,
  };
}

const WEIGHT: Record<string, number> = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };

/** The failed check that would improve the score the most. */
export function topRecommendation(results: CheckResult[]): CheckResult | undefined {
  return results
    .filter((r) => r.outcome === 'fail')
    .sort(
      (a, b) => (WEIGHT[b.severity] ?? 0) - (WEIGHT[a.severity] ?? 0) || a.id.localeCompare(b.id),
    )[0];
}
