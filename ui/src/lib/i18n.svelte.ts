// Fluent-based i18n. `en` is the source language; `pt-BR` is mandatory.
// Messages always take named arguments: never concatenate translations.
import { FluentBundle, FluentResource, type FluentVariable } from '@fluent/bundle';

export const LOCALES = ['en', 'pt-BR'] as const;
export type Locale = (typeof LOCALES)[number];

const uiFiles = import.meta.glob('../../locales/*/ui.ftl', {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>;
const pluginFiles = import.meta.glob('../../../plugins/*/locales/*.ftl', {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>;

function buildBundle(locale: Locale): FluentBundle {
  // Isolation marks are for mixed-direction text; they break plain-text tests.
  const bundle = new FluentBundle(locale, { useIsolating: false });
  const sources = [
    ...Object.entries(uiFiles).filter(([path]) => path.includes(`/${locale}/`)),
    ...Object.entries(pluginFiles).filter(([path]) => path.endsWith(`/${locale}.ftl`)),
  ];
  for (const [, text] of sources) {
    bundle.addResource(new FluentResource(text));
  }
  return bundle;
}

const bundles: Record<Locale, FluentBundle> = {
  en: buildBundle('en'),
  'pt-BR': buildBundle('pt-BR'),
};

export function detectLocale(): Locale {
  try {
    const saved = localStorage.getItem('ibexwall.locale');
    if (saved === 'en' || saved === 'pt-BR') return saved;
  } catch {
    /* storage unavailable */
  }
  return navigator.language.toLowerCase().startsWith('pt') ? 'pt-BR' : 'en';
}

class I18n {
  locale = $state<Locale>(detectLocale());

  set(locale: Locale) {
    this.locale = locale;
    try {
      localStorage.setItem('ibexwall.locale', locale);
    } catch {
      /* storage unavailable */
    }
    document.documentElement.lang = locale;
  }
}

export const i18n = new I18n();

/** Looks up a message; falls back to English, then to the key itself. */
export function t(key: string, args?: Record<string, FluentVariable>): string {
  for (const locale of [i18n.locale, 'en' as Locale]) {
    const bundle = bundles[locale];
    const message = bundle.getMessage(key);
    if (message?.value) {
      return bundle.formatPattern(message.value, args);
    }
  }
  return key;
}

/** True when a message exists in the active language (no fallback). */
export function has(key: string): boolean {
  return Boolean(bundles[i18n.locale].getMessage(key)?.value);
}

export function messageKeys(locale: Locale): string[] {
  const keys: string[] = [];
  for (const [, text] of Object.entries(uiFiles).filter(([p]) => p.includes(`/${locale}/`))) {
    for (const line of text.split('\n')) {
      const match = /^([a-z][a-z0-9-]*) =/.exec(line);
      if (match?.[1]) keys.push(match[1]);
    }
  }
  return keys.sort();
}
