/**
 * Where the explanation pages live: one page per hardening setting, at
 * `${DOCS_BASE}/hardening/<item id>`. The site is ibexwall.com and the
 * documentation is docs.ibexwall.com (P-01).
 */
export const DOCS_BASE = 'https://ibexwall.com';

export function docsUrl(slug: string): string | null {
  return DOCS_BASE ? `${DOCS_BASE}/hardening/${slug}` : null;
}
