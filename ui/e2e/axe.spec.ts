import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

// The build is what ships; accessibility is checked on the built app.
for (const theme of ['light', 'dark'] as const) {
  for (const locale of ['en', 'pt-BR'] as const) {
    test(`no serious axe violations (${theme}, ${locale})`, async ({ page }) => {
      await page.goto(`/?scenario=attention&theme=${theme}&locale=${locale}`);
      await page.evaluate(
        ([t, l]) => {
          if (t) document.documentElement.dataset['theme'] = t;
          localStorage.setItem('ibexwall.locale', l);
        },
        [theme, locale],
      );
      await page.reload();
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

      // Overview first, then the Apps and network screen (list, filters,
      // details) and the Secure DNS screen (a form with a flow).
      for (const screen of ['overview', 'firewall', 'apps', 'dns']) {
        if (screen === 'firewall') {
          await page.getByRole('button', { name: /firewall/i }).click();
          await expect(
            page.getByText(/managed by firewalld|gerenciado por firewalld/i),
          ).toBeVisible();
        }
        if (screen === 'apps') {
          await page.getByRole('button', { name: /apps and network|apps e rede/i }).click();
          await page
            .getByRole('button', { name: /details for firefox|detalhes de firefox/i })
            .click();
          await expect(page.getByText(/search\.duckduckgo\.com/)).toBeVisible();
        }
        if (screen === 'dns') {
          await page.getByRole('button', { name: /secure dns|dns seguro/i }).click();
          await expect(page.getByRole('radio').first()).toBeVisible();
        }
        const results = await new AxeBuilder({ page })
          .withTags(['wcag2a', 'wcag2aa', 'wcag22aa'])
          .analyze();
        const serious = results.violations.filter(
          (v) => v.impact === 'serious' || v.impact === 'critical',
        );
        expect(serious, `${screen}: ${JSON.stringify(serious, null, 2)}`).toEqual([]);
      }
    });
  }
}

test('keyboard navigation reaches every navigation item', async ({ page }) => {
  await page.goto('/?scenario=attention');
  const overview = page.getByRole('button', { name: 'Overview' });
  await overview.focus();
  for (let step = 0; step < 8; step += 1) {
    await page.keyboard.press('Tab');
  }
  // After the nav, focus moves into the content: the "Check now" button.
  await expect(page.getByRole('button', { name: /check now/i })).toBeFocused();
});

test('the skip link jumps to the content', async ({ page }) => {
  await page.goto('/?scenario=attention');
  await page.keyboard.press('Tab');
  const skip = page.getByRole('link', { name: /skip to content/i });
  await expect(skip).toBeFocused();
  await skip.press('Enter');
  await expect(page.locator('#content')).toBeFocused();
});
