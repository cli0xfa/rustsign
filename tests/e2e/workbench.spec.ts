import { test, expect } from '@playwright/test';
import { bridge } from './bridge';

test('boot layer remains painted until the first workspace frame', async ({ page }) => {
  await bridge(page);
  let releaseScript!: () => void;
  const scriptGate = new Promise<void>((resolve) => {
    releaseScript = resolve;
  });
  await page.route('**/assets/*.js', async (route) => {
    await scriptGate;
    await route.continue();
  });
  await page.goto('/', { waitUntil: 'commit' });
  const boot = page.locator('#app-boot');
  await expect(boot).toBeVisible();
  await expect(page.getByRole('status')).toContainText('正在加载工作台');
  const colors = await boot.evaluate((element) => ({
    boot: getComputedStyle(element).backgroundColor,
    body: getComputedStyle(document.body).backgroundColor,
  }));
  expect(colors.boot).toBe(colors.body);

  releaseScript();
  await expect(page.getByRole('heading', { name: '文件工作台', exact: true })).toBeVisible();
  await expect(boot).toHaveCSS('visibility', 'hidden');
});

test('drag hint, disclosures, and operation results use restrained state motion', async ({
  page,
}) => {
  await bridge(page, { failSign: true });
  await page.goto('/');
  await page.evaluate(() => {
    const animations: string[] = [];
    (window as Window & { __motionAnimations?: string[] }).__motionAnimations = animations;
    document.addEventListener('animationstart', (event) => {
      animations.push((event as AnimationEvent).animationName);
    });
  });

  await page.evaluate(() => {
    const transfer = new DataTransfer();
    const file = new File(['binary'], 'client.exe');
    Object.defineProperty(file, 'path', { value: 'C:\\build\\client.exe' });
    transfer.items.add(file);
    window.dispatchEvent(new DragEvent('dragenter', { bubbles: true, dataTransfer: transfer }));
  });
  const dropHint = page.locator('.drop-overlay-card');
  await expect(dropHint).toBeVisible();
  await expect
    .poll(() => dropHint.evaluate((element) => getComputedStyle(element).animationName))
    .toBe('drop-card-in');
  await page.evaluate(() => window.dispatchEvent(new Event('blur')));
  await expect(page.locator('.drop-overlay')).toHaveCount(0);

  await page.getByRole('button', { name: '选择 PE 文件' }).click();
  const advanced = page.getByRole('button', { name: /高级选项/ });
  await advanced.focus();
  await page.keyboard.press('Space');
  await expect(advanced).toHaveAttribute('aria-expanded', 'true');
  const details = page.locator(`#${await advanced.getAttribute('aria-controls')}`);
  await expect(details).toHaveAttribute('aria-hidden', 'false');
  await advanced.press('Enter');
  await expect(advanced).toHaveAttribute('aria-expanded', 'false');
  await expect(details).toHaveAttribute('aria-hidden', 'true');
  await advanced.press('Enter');

  await page.getByLabel('签名证书', { exact: true }).selectOption('test-identity');
  await page.getByRole('button', { name: '开始签名' }).click();
  await expect(page.getByText('签名未完成，请检查证书及签名参数。', { exact: true })).toBeVisible();
  const resultAnimationCount = () =>
    page.evaluate(
      () =>
        (window as Window & { __motionAnimations?: string[] }).__motionAnimations?.filter(
          (name) => name === 'result-in',
        ).length ?? 0,
    );
  await expect.poll(resultAnimationCount).toBeGreaterThanOrEqual(1);
  await page.getByRole('button', { name: '开始签名' }).click();
  await expect(page.getByText('签名已写入原文件', { exact: true })).toBeVisible();
  await expect.poll(resultAnimationCount).toBeGreaterThanOrEqual(2);
});

test('reduced motion removes travel and keeps immediate state feedback', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await bridge(page);
  await page.goto('/');
  const durations = await page.evaluate(() => ({
    boot: getComputedStyle(document.getElementById('app-boot')!).transitionDuration,
    panel: getComputedStyle(document.querySelector('.task-content')!).animationDuration,
    panelAnimation: getComputedStyle(document.querySelector('.task-content')!).animationName,
  }));
  expect(parseFloat(durations.boot)).toBeLessThan(0.001);
  expect(parseFloat(durations.panel)).toBeLessThan(0.001);
  expect(durations.panelAnimation).toBe('none');
});

test('file → import → return → sign → verify without losing the draft', async ({ page }) => {
  await bridge(page, { empty: true });
  await page.goto('/');
  await page.getByRole('button', { name: '选择 PE 文件' }).click();
  await page.getByText('高级选项').click();
  await page.getByLabel('程序描述', { exact: true }).fill('Production build 42');
  await page.getByRole('button', { name: '前往证书库' }).click();
  await page.getByRole('button', { name: '导入证书' }).first().click();
  await page.getByRole('dialog').getByRole('button', { name: '导入证书' }).click();
  await expect(page.getByText('Acme Software Signing', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '返回文件工作台' }).click();
  await expect(page.getByLabel('完整路径')).toContainText('client.exe');
  await page.getByText('高级选项').click();
  await expect(page.getByLabel('程序描述', { exact: true })).toHaveValue('Production build 42');
  await page.getByLabel('签名证书', { exact: true }).selectOption('imported-0');
  await page.getByRole('button', { name: '开始签名' }).click();
  await expect(page.getByText('签名已写入原文件', { exact: true })).toBeVisible();
  await expect(page.getByText('签名已写入原文件', { exact: true })).toBeInViewport();
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.locator('.page-scroll').evaluate((element) => {
    element.scrollTop = 0;
  });
  await page.screenshot({ path: 'artifacts/workbench-preview.png' });
  await page.getByRole('tab', { name: '验证', exact: true }).click();
  await page.getByRole('button', { name: '验证签名' }).click();
  await expect(page.getByText('CMS 签名与文件摘要校验通过', { exact: true })).toBeVisible();
  await page.getByRole('tab', { name: '管理签名', exact: true }).click();
  await expect(page.getByRole('button', { name: '上移签名 1', exact: true })).toBeDisabled();
});

test('destructive confirmation supports keyboard cancel and restores focus', async ({ page }) => {
  await bridge(page, { signed: true });
  await page.goto('/');
  await page.evaluate(() => {
    const animations: string[] = [];
    (window as Window & { __dialogAnimations?: string[] }).__dialogAnimations = animations;
    document.addEventListener('animationstart', (event) => {
      animations.push((event as AnimationEvent).animationName);
    });
  });
  await page.getByRole('button', { name: '选择 PE 文件' }).click();
  await page.getByLabel('签名证书', { exact: true }).selectOption('test-identity');
  const sign = page.getByRole('button', { name: '开始签名' });
  await sign.click();
  await expect(page.getByRole('alertdialog')).toBeVisible();
  await expect
    .poll(() =>
      page
        .locator('.dialog-content')
        .evaluate((element) => getComputedStyle(element).animationName),
    )
    .toBe('dialog-in');
  await expect(page.getByRole('button', { name: '取消', exact: true })).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(sign).toBeFocused();
  await expect
    .poll(() =>
      page.evaluate(
        () => (window as Window & { __dialogAnimations?: string[] }).__dialogAnimations ?? [],
      ),
    )
    .toContain('dialog-out');
  await page.getByRole('tab', { name: '管理签名' }).click();
  await page.getByRole('button', { name: '移除此签名 1', exact: true }).click();
  await expect(page.getByRole('alertdialog')).toContainText('client.exe');
  await page.getByRole('button', { name: '确认执行' }).click();
  await expect(page.locator('[role="tabpanel"] ol > li')).toHaveCount(1);
  await expect(page.locator('[role="tabpanel"] ol')).toContainText('Acme Legacy Signing');
});

test('certificate detail drawer animates out and returns focus to its opener', async ({ page }) => {
  await bridge(page);
  await page.goto('/');
  await page.evaluate(() => {
    const animations: string[] = [];
    (window as Window & { __drawerAnimations?: string[] }).__drawerAnimations = animations;
    document.addEventListener('animationstart', (event) => {
      animations.push((event as AnimationEvent).animationName);
    });
  });
  await page.getByRole('button', { name: '证书库', exact: true }).click();
  const view = page.getByRole('button', { name: '查看 Acme Software Signing' });
  await view.click();
  const drawer = page.getByRole('dialog');
  await expect(drawer).toBeVisible();
  await expect
    .poll(() => drawer.evaluate((element) => getComputedStyle(element).animationName))
    .toBe('drawer-in');
  await page.getByRole('button', { name: '关闭', exact: true }).first().click();
  await expect(view).toBeFocused();
  await expect(drawer).toHaveCount(0);
  await expect
    .poll(() =>
      page.evaluate(
        () => (window as Window & { __drawerAnimations?: string[] }).__drawerAnimations ?? [],
      ),
    )
    .toContain('drawer-out');
});

test('keyboard signing, verification, tab navigation and destructive cancel', async ({ page }) => {
  await bridge(page);
  await page.goto('/');
  await page.getByRole('button', { name: '选择 PE 文件' }).focus();
  await page.keyboard.press('Enter');
  const certificate = page.getByLabel('签名证书', { exact: true });
  await certificate.focus();
  await expect(certificate).toBeFocused();
  // Native select popups commit keyboard choices differently across host OSes.
  await certificate.selectOption('test-identity');
  await expect(certificate).toHaveValue('test-identity');
  await page.getByRole('button', { name: '开始签名' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByText('签名已写入原文件', { exact: true })).toBeVisible();
  await page.getByRole('tab', { name: '签名', exact: true }).focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: '验证', exact: true })).toHaveAttribute(
    'aria-selected',
    'true',
  );
  await page.getByRole('button', { name: '验证签名' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByText('CMS 签名与文件摘要校验通过', { exact: true })).toBeVisible();
  await page.getByRole('tab', { name: '验证', exact: true }).focus();
  await page.keyboard.press('ArrowRight');
  const remove = page.getByRole('button', { name: '移除此签名 1', exact: true });
  await remove.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('button', { name: '取消', exact: true })).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(remove).toBeFocused();
});

test('certificate read failure is recoverable and filtering clears bulk selection', async ({
  page,
}) => {
  await bridge(page, { failCertificates: true });
  await page.goto('/');
  await page.getByRole('button', { name: '证书库', exact: true }).click();
  await expect(page.getByRole('heading', { name: '无法读取证书库' })).toBeVisible();
  await expect(page.getByText('暂无证书', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: '重试', exact: true }).click();
  await page.getByRole('checkbox', { name: '全选', exact: true }).check();
  await expect(page.getByRole('button', { name: '删除所选' })).toBeEnabled();
  await page.getByLabel('搜索名称、颁发者或指纹').fill('Legacy');
  await expect(page.getByRole('button', { name: '删除所选' })).toBeDisabled();
  await expect(page.locator('tbody tr')).toHaveCount(1);
  await page.getByLabel('有效期', { exact: true }).selectOption('valid');
  await expect(page.getByText('没有匹配的证书', { exact: true })).toBeVisible();
});

test('writing locks the file but navigation and task result survive', async ({ page }) => {
  await bridge(page, { slowSign: true });
  await page.goto('/');
  await page.getByRole('button', { name: '选择 PE 文件' }).click();
  await page.getByLabel('签名证书', { exact: true }).selectOption('test-identity');
  await page.getByRole('button', { name: '开始签名' }).click();
  await expect(page.getByRole('button', { name: '更换文件' })).toBeDisabled();
  await page.getByRole('button', { name: '证书库', exact: true }).click();
  await page.getByRole('button', { name: '返回文件工作台' }).click();
  await expect(page.getByText('签名已写入原文件', { exact: true })).toBeVisible();
});

test('a failed signing operation retains configuration and can be retried', async ({ page }) => {
  await bridge(page, { failSign: true });
  await page.goto('/');
  await page.getByRole('button', { name: '选择 PE 文件' }).click();
  await page.getByLabel('签名证书', { exact: true }).selectOption('test-identity');
  await page.getByLabel('摘要算法', { exact: true }).selectOption('sha512');
  await page.getByRole('button', { name: '开始签名' }).click();
  await expect(page.getByText('签名未完成，请检查证书及签名参数。', { exact: true })).toBeVisible();
  await expect(page.getByLabel('摘要算法', { exact: true })).toHaveValue('sha512');
  await expect(page.getByLabel('签名证书', { exact: true })).toHaveValue('test-identity');
  await page.getByRole('button', { name: '开始签名' }).click();
  await expect(page.getByText('签名已写入原文件', { exact: true })).toBeVisible();
});

test('generation paths, private-key gating, and TSA local time', async ({ page }) => {
  await bridge(page);
  await page.goto('/');
  await page.getByRole('button', { name: '证书库', exact: true }).click();
  await page.getByRole('button', { name: '生成测试证书' }).click();
  await expect(page.getByLabel('PFX 密码', { exact: true })).toHaveAttribute('type', 'password');
  await page.getByRole('button', { name: '生成证书', exact: true }).click();
  await expect(page.getByText('C:\\export\\generated.pfx', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '时间戳服务', exact: true }).click();
  await page.getByLabel('签名证书', { exact: true }).selectOption('test-identity');
  await page.getByLabel('启用自定义签名时间').check();
  await page.getByLabel('自定义时间', { exact: true }).fill('2026-10-24T13:14:15');
  await page.getByRole('button', { name: '启动服务器', exact: true }).click();
  await expect(page.getByLabel('监听端口', { exact: true })).toBeDisabled();
  await expect(page.getByText('http://127.0.0.1:18080', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '停止服务器', exact: true }).click();
  await expect(page.getByLabel('监听端口', { exact: true })).toBeEnabled();
});

for (const [width, height] of [
  [500, 480],
  [640, 600],
  [900, 680],
  [960, 720],
  [1280, 800],
]) {
  for (const language of ['zh-CN', 'en'])
    for (const theme of ['dark', 'light']) {
      test(`layout ${width}×${height} ${language} ${theme}`, async ({ page }) => {
        await page.setViewportSize({ width, height });
        await bridge(page, { language, theme, longPath: true });
        await page.goto('/');
        const en = language === 'en';
        await page
          .getByRole('button', { name: en ? 'Choose PE file' : '选择 PE 文件', exact: true })
          .click();
        await expect(page.getByLabel(en ? 'Full path' : '完整路径')).toBeVisible();
        const action = page.getByRole('button', { name: en ? 'Sign' : '开始签名', exact: true });
        const box = await action.boundingBox();
        expect(box!.y + box!.height).toBeLessThanOrEqual(height);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
          true,
        );
        await page.screenshot({ path: `artifacts/workbench-${width}-${language}-${theme}.png` });
        if (width < 640)
          await page
            .getByRole('button', { name: en ? 'Toggle workspace navigation' : '切换工作区导航' })
            .click();
        await page
          .getByRole('button', { name: en ? 'Certificate library' : '证书库', exact: true })
          .click();
        await expect(page.locator('tbody tr')).toHaveCount(3);
        if (width < 640) await expect(page.locator('.dialog-overlay')).toHaveCount(0);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
          true,
        );
        await page.screenshot({ path: `artifacts/certificates-${width}-${language}-${theme}.png` });
        if (width < 640)
          await page
            .getByRole('button', { name: en ? 'Toggle workspace navigation' : '切换工作区导航' })
            .click();
        await page.getByRole('button', { name: en ? 'TSA' : '时间戳服务', exact: true }).click();
        await expect(
          page.getByLabel(en ? 'Listen port' : '监听端口', { exact: true }),
        ).toBeVisible();
        if (width < 640) await expect(page.locator('.dialog-overlay')).toHaveCount(0);
        await page.screenshot({ path: `artifacts/tsa-${width}-${language}-${theme}.png` });
      });
    }
}

for (const theme of ['dark', 'light']) {
  test(`text and essential control contrast ${theme}`, async ({ page }) => {
    await bridge(page, { theme });
    await page.goto('/');
    await expect(page.getByRole('heading', { name: '文件工作台', exact: true })).toBeVisible();
    const colors = await page.evaluate(() => {
      const tokens = [
        'background',
        'foreground',
        'card',
        'muted-foreground',
        'primary',
        'primary-foreground',
        'error',
        'error-bg',
        'success',
        'success-bg',
        'warning',
        'warning-bg',
        'info',
        'info-bg',
        'input',
      ];
      const values: Record<string, string> = {};
      const root = getComputedStyle(document.documentElement);
      for (const token of tokens) {
        const probe = document.createElement('span');
        probe.style.color = `hsl(${root.getPropertyValue(`--${token}`)})`;
        document.body.append(probe);
        values[token] = getComputedStyle(probe).color;
        probe.remove();
      }
      return values;
    });
    const luminance = (color: string) =>
      color
        .match(/[\d.]+/g)!
        .slice(0, 3)
        .map(Number)
        .map((value) => {
          const channel = value / 255;
          return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
        })
        .reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
    for (const [foreground, background, minimum] of [
      ['foreground', 'background', 4.5],
      ['muted-foreground', 'background', 4.5],
      ['muted-foreground', 'card', 4.5],
      ['primary-foreground', 'primary', 4.5],
      ['error', 'error-bg', 4.5],
      ['success', 'success-bg', 4.5],
      ['warning', 'warning-bg', 4.5],
      ['info', 'info-bg', 4.5],
      ['input', 'card', 3],
    ] as const) {
      const first = luminance(colors[foreground]);
      const second = luminance(colors[background]);
      expect(
        (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05),
        `${foreground} / ${background}`,
      ).toBeGreaterThanOrEqual(minimum);
    }
  });
}
