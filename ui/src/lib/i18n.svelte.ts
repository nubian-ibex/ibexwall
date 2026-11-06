// Fluent-based i18n. `en` is the source language and the fallback; the app
// follows the system language unless the person picks one.
// Messages always take named arguments: never concatenate translations.
import { FluentBundle, FluentResource, type FluentVariable } from '@fluent/bundle';

/** The source language; every message exists in it, and it is the fallback. */
export const SOURCE_LOCALE = 'en';

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

/**
 * Every language the app ships, found from the folders under `ui/locales`:
 * adding a language is adding `ui/locales/<tag>/ui.ftl` and the plugins'
 * `locales/<tag>.ftl`, with no code to change.
 */
export const LOCALES: string[] = [
  SOURCE_LOCALE,
  ...Object.keys(uiFiles)
    .map((path) => /locales\/([^/]+)\/ui\.ftl$/.exec(path)?.[1] ?? '')
    .filter((tag) => tag !== '' && tag !== SOURCE_LOCALE)
    .sort(),
];
export type Locale = string;

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

const bundles: Record<Locale, FluentBundle> = Object.fromEntries(
  LOCALES.map((locale) => [locale, buildBundle(locale)]),
);

/**
 * The shipped language that best fits the languages the system asks for, in
 * its order: an exact tag first (`pt-BR`), then the same language (`pt-PT`
 * gets `pt-BR`, `es-MX` gets `es`). English when nothing fits.
 */
export function negotiate(
  requested: readonly string[],
  available: readonly string[] = LOCALES,
): Locale {
  const find = (tag: string) => available.find((a) => a.toLowerCase() === tag);
  for (const tag of requested) {
    const wanted = tag.toLowerCase().replace('_', '-');
    const exact = find(wanted);
    if (exact) return exact;
    const language = wanted.split('-')[0] ?? '';
    const sameLanguage =
      find(language) ?? available.find((a) => a.toLowerCase().split('-')[0] === language);
    if (sameLanguage) return sameLanguage;
  }
  return SOURCE_LOCALE;
}

const STORAGE_KEY = 'ibexwall.locale';

/** The language the system asks for (the webview follows the session's locale). */
export function systemLocale(): Locale {
  const asked =
    typeof navigator === 'undefined'
      ? []
      : navigator.languages?.length
        ? navigator.languages
        : [navigator.language];
  return negotiate(asked.filter(Boolean));
}

/** The person's own choice, or the system's language when there is none. */
export function detectLocale(): Locale {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && LOCALES.includes(saved)) return saved;
  } catch {
    /* storage unavailable */
  }
  return systemLocale();
}

/** A language's own name, in that language ("Português (Brasil)"). */
export function languageName(locale: Locale): string {
  try {
    const name = new Intl.DisplayNames([locale], { type: 'language' }).of(locale);
    if (name) return name.charAt(0).toLocaleUpperCase(locale) + name.slice(1);
  } catch {
    /* unknown tag */
  }
  return locale;
}

class I18n {
  locale = $state<Locale>(detectLocale());

  /** Sets the language; `null` goes back to following the system. */
  set(locale: Locale | null) {
    try {
      if (locale === null) localStorage.removeItem(STORAGE_KEY);
      else localStorage.setItem(STORAGE_KEY, locale);
    } catch {
      /* storage unavailable */
    }
    this.locale = locale ?? systemLocale();
    document.documentElement.lang = this.locale;
  }

  /** Whether the language is the person's choice (false: follows the system). */
  get chosen(): boolean {
    try {
      return localStorage.getItem(STORAGE_KEY) !== null;
    } catch {
      return false;
    }
  }
}

export const i18n = new I18n();

/** Looks up a message; falls back to English, then to the key itself. */
export function t(key: string, args?: Record<string, FluentVariable>): string {
  for (const locale of [i18n.locale, SOURCE_LOCALE]) {
    const bundle = bundles[locale];
    const message = bundle?.getMessage(key);
    if (bundle && message?.value) {
      return bundle.formatPattern(message.value, args);
    }
  }
  return key;
}

/** True when a message exists in the active language (no fallback). */
export function has(key: string): boolean {
  return Boolean(bundles[i18n.locale]?.getMessage(key)?.value);
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
