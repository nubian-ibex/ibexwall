import { describe, expect, it } from 'vitest';
import type { CheckResult, Posture } from '../gen/contracts';
import { counts, overallStatus, topRecommendation } from './status';
import { cardsFrom, cardState } from './protections';

const c = (
  id: string,
  severity: CheckResult['severity'],
  outcome: CheckResult['outcome'],
): CheckResult => ({ id, severity, outcome });

const posture = (score: number | null, results: CheckResult[]): Posture => ({
  score,
  generated_at: '2026-11-01T12:00:00Z',
  protections: [],
  open_findings: 0,
  results,
});

describe('overallStatus', () => {
  it('is unknown without a score', () => {
    expect(overallStatus(posture(null, []))).toBe('unknown');
  });
  it('is protected only with a high score and no serious failure', () => {
    expect(overallStatus(posture(95, [c('a', 'low', 'fail')]))).toBe('protected');
    expect(overallStatus(posture(95, [c('a', 'high', 'fail')]))).toBe('attention');
    expect(overallStatus(posture(70, []))).toBe('attention');
  });
});

describe('counts and recommendation', () => {
  const results = [
    c('a', 'low', 'fail'),
    c('b', 'high', 'fail'),
    c('c', 'medium', 'pass'),
    c('d', 'high', 'not_assessed'),
    c('e', 'info', 'not_applicable'),
  ];
  it('counts assessed, passed, failed and not assessed', () => {
    expect(counts(results)).toEqual({ assessed: 3, passed: 1, failed: 2, notAssessed: 1 });
  });
  it('recommends the failed check with the most weight', () => {
    expect(topRecommendation(results)?.id).toBe('b');
    expect(topRecommendation([c('x', 'low', 'pass')])).toBeUndefined();
  });
});

describe('protection cards', () => {
  it('groups checks and derives the card state', () => {
    const cards = cardsFrom([
      c('posture.secure_boot', 'medium', 'pass'),
      c('posture.lockdown', 'low', 'fail'),
      c('posture.firewall', 'high', 'pass'),
    ]);
    expect(cards.map((card) => [card.id, card.state])).toEqual([
      ['boot', 'attention'],
      ['firewall', 'ok'],
    ]);
  });
  it('only shows cards that have results and never turns unknown into ok', () => {
    expect(cardsFrom([])).toEqual([]);
    expect(cardState([c('x', 'low', 'not_assessed'), c('y', 'low', 'not_applicable')])).toBe(
      'unknown',
    );
  });
});
