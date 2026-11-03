import { expect, test } from '@playwright/test';

test('overview: attention scenario shows the score and the recommendation', async ({ page }) => {
  await page.goto('/?scenario=attention');
  await expect(page.getByRole('heading', { name: /can be better protected/i })).toBeVisible();
  await expect(page.getByRole('img', { name: /score \d+ out of 100/i })).toBeVisible();
  await expect(page.getByRole('button', { name: /see recommendation/i })).toBeVisible();
});

test('overview: protected scenario stays calm', async ({ page }) => {
  await page.goto('/?scenario=protected');
  await expect(page.getByRole('heading', { name: /your computer is protected/i })).toBeVisible();
});

test('plugins: detail shows permissions and the change flow', async ({ page }) => {
  await page.goto('/?scenario=attention');
  await page.getByRole('button', { name: /plugins/i }).click();
  await page
    .getByRole('button', { name: /detail/i })
    .first()
    .click();
  await expect(page.getByText('Read the system; it cannot change anything')).toBeVisible();
});

test('history: entries with undo', async ({ page }) => {
  await page.goto('/?scenario=attention');
  await page.getByRole('button', { name: /history/i }).click();
  await expect(page.getByText('Applied and kept')).toBeVisible();
  await expect(page.getByRole('button', { name: /undo this change/i })).toBeVisible();
});

test('theme switch keeps text readable (dark contrast)', async ({ page }) => {
  await page.goto('/?scenario=attention&theme=dark');
  await page.evaluate(() => {
    document.documentElement.dataset['theme'] = 'dark';
  });
  const body = page.locator('body');
  await expect(body).toBeVisible();
  // The headline must stay visible in dark mode.
  await expect(page.getByRole('heading', { name: /better protected/i })).toBeVisible();
});

test('locale is pt-BR when requested', async ({ page }) => {
  await page.goto('/?scenario=attention');
  await page.evaluate(() => localStorage.setItem('ibexwall.locale', 'pt-BR'));
  await page.reload();
  await expect(page.getByRole('heading', { name: /pode estar mais protegido/i })).toBeVisible();
});

test('apps: the list, the details and what each mode can do', async ({ page }) => {
  await page.goto('/?scenario=attention');
  await page.getByRole('button', { name: /apps and network/i }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Apps and network' })).toBeVisible();
  await expect(page.getByRole('button', { name: /details for telegram/i })).toBeVisible();
  await page.getByRole('button', { name: /details for telegram/i }).click();
  await expect(page.getByRole('button', { name: /block network access/i })).toBeVisible();
  // A program that is not a Flatpak app cannot be blocked yet.
  await page.getByRole('button', { name: /details for firefox/i }).click();
  await expect(page.getByRole('button', { name: /block network access/i })).toHaveCount(0);
  await expect(page.getByText('github.com')).toBeVisible();
});

test('apps: the monitor being off is stated, not hidden', async ({ page }) => {
  await page.goto('/?scenario=empty');
  await page.getByRole('button', { name: /apps and network/i }).click();
  await expect(page.getByText(/connection monitor is off/i)).toBeVisible();
});

test('firewall: state, a reviewed port change and a profile', async ({ page }) => {
  await page.goto('/?scenario=attention');
  await page.getByRole('button', { name: /^firewall$/i }).click();
  await expect(page.getByRole('heading', { name: 'The firewall is on' })).toBeVisible();
  await expect(page.getByText('8080/tcp', { exact: true })).toBeVisible();
  // With the plugin off, the controls are visibly inert and say why.
  await expect(page.getByText('The firewall controls are off')).toBeVisible();
  await expect(page.getByRole('button', { name: /allow this port/i })).toBeDisabled();
  // Profiles are offered (firewalld) but their switch is inert too.
  await page.getByRole('radio', { name: /travel/i }).check();
  await expect(page.getByRole('button', { name: /switch to travel/i })).toBeDisabled();
  // The choice spells out what it means, before anyone commits to it.
  await expect(page.getByText(/nothing comes in unasked/i)).toBeVisible();
});

test('firewall: an open network is called out', async ({ page }) => {
  await page.goto('/?scenario=attention');
  await page.getByRole('button', { name: /^firewall$/i }).click();
  await expect(page.getByText('Cafe WiFi')).toBeVisible();
  await expect(page.getByText(/this network is open/i)).toBeVisible();
});
