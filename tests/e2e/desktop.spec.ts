import { test, expect } from '@playwright/test';
import { bridge } from './bridge';

test('titlebar actions, native menu requests and menu keyboard focus work', async ({ page }) => {
  await bridge(page);
  await page.goto('/');
  const file = page.getByRole('menuitem', { name: '文件', exact: true });
  await file.focus();
  await page.keyboard.press('ArrowDown');
  await expect(page.getByRole('menuitem', { name: /打开 PE 文件/ })).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(file).toBeFocused();
  await page.getByRole('button', { name: '最大化', exact: true }).click();
  await expect(page.getByRole('button', { name: '还原', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '还原', exact: true }).click();
  await expect(page.getByRole('button', { name: '最大化', exact: true })).toBeVisible();
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('desktop://window-menu')));
  await expect(page.getByRole('menuitem', { name: '移动', exact: true })).toBeVisible();
  await expect(page.getByRole('menuitem', { name: '还原', exact: true })).toHaveAttribute(
    'data-disabled',
    '',
  );
  await page.keyboard.press('Escape');
  await page.keyboard.press('Control+o');
  await expect(page.getByLabel('完整路径')).toBeVisible();
  await expect(page).toHaveTitle('文件工作台 · client.exe — RustSign');
});

test('compact menus retain theme, language and workspace access at 500px', async ({ page }) => {
  await page.setViewportSize({ width: 500, height: 480 });
  await bridge(page);
  await page.goto('/');
  await page.getByRole('button', { name: '应用菜单', exact: true }).click();
  await page.getByRole('menuitem', { name: '视图', exact: true }).hover();
  await page.getByRole('menuitemradio', { name: '浅色', exact: true }).click();
  await expect(page.locator('html')).not.toHaveClass('dark');
  await page.getByRole('button', { name: '应用菜单', exact: true }).click();
  await page.getByRole('menuitem', { name: '视图', exact: true }).hover();
  await page.getByRole('menuitemradio', { name: 'English', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'File workspace', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Toggle workspace navigation' }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.getByRole('button', { name: 'Certificate library', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Certificate library', exact: true }),
  ).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect
    .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
    .toBe(true);
});

test('close protection handles busy tasks and confirms TSA shutdown', async ({ page }) => {
  await bridge(page, { runningTsa: true });
  await page.goto('/');
  await page.getByRole('button', { name: '关闭窗口' }).click();
  await expect(page.getByRole('alertdialog')).toContainText('停止时间戳服务并退出');
  await expect(page.getByRole('button', { name: '取消', exact: true })).toBeFocused();
  await page.getByRole('button', { name: '取消', exact: true }).click();
  await expect(page.getByRole('alertdialog')).toHaveCount(0);
  await page.evaluate(() =>
    window.dispatchEvent(new CustomEvent('desktop://close-state', { detail: 'busy' })),
  );
  await expect(page.getByText('任务正在执行，请等待任务完成后退出。')).toBeVisible();
  await expect(page.getByRole('alertdialog')).toHaveCount(0);
});
