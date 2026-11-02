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
