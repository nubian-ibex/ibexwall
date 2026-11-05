/**
 * Where the explanation pages live. The domain is not decided yet (P-01), so
 * this stays empty and the screens show no link to the site; the sources
 * each item cites are always shown. Set it to `https://<domain>` when the
 * site exists: an item's page is `${DOCS_BASE}/hardening/<item id>`.
 */
export const DOCS_BASE = '';

export function docsUrl(slug: string): string | null {
  return DOCS_BASE ? `${DOCS_BASE}/hardening/${slug}` : null;
}
