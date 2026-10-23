async function nativeSmoke(config) {
  const checks = [];
  const invoke = (...args) => window.__TAURI__.core.invoke(...args);
  const wait = async (condition, description) => {
    const deadline = Date.now() + 25000;
    while (!condition()) {
      if (Date.now() > deadline) throw new Error(`Timed out: ${description}`);
      await new Promise((resolve) => setTimeout(resolve, 40));
    }
  };
  const setSelect = (id, value) => {
    const element = document.getElementById(id);
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(element, value);
    element.dispatchEvent(new Event('change', { bubbles: true }));
  };
  const tick = () => new Promise((resolve) => setTimeout(resolve, 100));
  try {
    await wait(() => document.querySelector('.task-tabs'), 'React workbench mounted');
    await wait(() => {
      const boot = document.getElementById('app-boot');
      return boot?.dataset.dismissed === 'true' && getComputedStyle(boot).visibility === 'hidden' && document.documentElement.dataset.desktopReady === 'true';
    }, 'native startup handoff completed after workspace paint');
    let desktop = await invoke('desktop_smoke_probe', { action: 'inspect' });
    if (!desktop.visible || desktop.chrome.nativeTitlebar || desktop.chrome.hit !== 9 || !desktop.chrome.visible) throw new Error('Frameless window or native Snap region missing: ' + JSON.stringify(desktop));
    const maximizeRect = document.querySelector('.window-controls button:nth-child(2)').getBoundingClientRect();
    if (Math.abs(desktop.chrome.width - maximizeRect.width * desktop.scale) > 1 || Math.abs(desktop.chrome.height - maximizeRect.height * desktop.scale) > 1) throw new Error('Snap region DPI mismatch');
    checks.push('visible native startup handoff, custom frame and HTMAXBUTTON region at the actual display DPI');
    await invoke('desktop_smoke_probe', { action: 'minimize' });
    await invoke('complete_startup', { theme: document.documentElement.classList.contains('dark') ? 'dark' : 'light' });
    desktop = await invoke('desktop_smoke_probe', { action: 'inspect' });
    if (!desktop.minimized) throw new Error('Repeated startup handshake unexpectedly revealed the window');
    await invoke('desktop_smoke_probe', { action: 'unminimize' });
    await invoke('desktop_smoke_probe', { action: 'maximize' }); await tick();
    await wait(() => document.querySelector('button[aria-label="还原"],button[aria-label="Restore"]'), 'maximize button state');
    await invoke('desktop_smoke_probe', { action: 'restore' }); await tick();
    await window.__TAURI__.window.getCurrentWindow().toggleMaximize(); await tick();
    desktop = await invoke('desktop_smoke_probe', { action: 'inspect' });
    if (!desktop.maximized) throw new Error('Official JavaScript maximize API failed');
    await invoke('desktop_smoke_probe', { action: 'restore' }); await tick();
    await invoke('desktop_smoke_probe', { action: 'emit-caption' }); await tick();
    desktop = await invoke('desktop_smoke_probe', { action: 'inspect' });
    if (!desktop.maximized) throw new Error('Native caption event did not reach the shell');
    await invoke('desktop_smoke_probe', { action: 'restore' }); await tick();
    await invoke('desktop_smoke_probe', { action: 'caption-click' }); await tick();
    desktop = await invoke('desktop_smoke_probe', { action: 'inspect' });
    if (!desktop.maximized) throw new Error('Native nonclient mouse messages did not maximize once');
    await invoke('desktop_smoke_probe', { action: 'caption-click' }); await tick();
    desktop = await invoke('desktop_smoke_probe', { action: 'inspect' });
    if (desktop.maximized) throw new Error('Native nonclient mouse messages did not restore once');
    if (await invoke('desktop_smoke_probe', { action: 'busy-close' }) !== 'busy') throw new Error('Native close bypassed an active task');
    checks.push('real minimize/maximize/restore, idempotent startup and backend close protection');
    await invoke('desktop_smoke_probe', { action: 'window-menu' });
    await wait(() => document.querySelector('[role="menu"]'), 'native Alt+Space system command opened custom window menu');
    await tick();
    desktop = await invoke('desktop_smoke_probe', { action: 'inspect' });
    if (desktop.chrome.visible) throw new Error('Native maximize region stayed above an open menu');
    checks.push('native system-menu command opens the custom menu and suspends the Snap overlay');
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    document.body.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true }));
    await tick();
    checks.push('native WebView2 loaded the production frontend');
    const result = await invoke('import_certificate', { filePath: config.cert, password: null });
    if (!result.success) throw new Error(result.message);
    const certificates = await invoke('list_certificates');
    if (!certificates.length || certificates[0].has_private_key !== true || !certificates[0].not_after_secs) throw new Error('Runtime certificate metadata missing');
    checks.push('real Tauri IPC import and runtime certificate metadata');
    const libraryButton = document.querySelectorAll('nav button')[1];
    libraryButton.click(); await tick();
    document.querySelector('button[aria-label="刷新"],button[aria-label="Refresh"]').click();
    await wait(() => document.querySelector('table'), 'certificate table');
    document.querySelectorAll('nav button')[0].click();
    await wait(() => document.querySelector('.task-tabs'), 'return to workbench');
    await window.__TAURI__.event.emitTo('main', 'tauri://drag-drop', { paths: [config.file], position: { x: 100, y: 100 } });
    await wait(() => document.querySelector('[aria-label="完整路径"],[aria-label="Full path"]'), 'native file drop');
    await wait(() => Array.from(document.querySelectorAll('#sign-certificate option')).some((option) => option.value === certificates[0].id), 'shared library refresh');
    setSelect('sign-certificate', certificates[0].id); setSelect('timestamp-service', '');
    await tick();
    await wait(() => !document.querySelector('.operation-bar button').disabled, 'sign action enabled');
    document.querySelector('.operation-bar button').click();
    await wait(() => document.querySelector('.result-column').textContent.includes('签名已写入原文件') || document.querySelector('.result-column').textContent.includes('Signature written to original file'), 'native signing result');
    checks.push('native file drop, preserved shared context and UI signing');
    const verified = await invoke('verify_pe_signature', { filePath: config.file });
    if (!verified.valid) throw new Error(verified.message);
    const verifyTab = document.querySelectorAll('[role="tab"]')[1];
    verifyTab.focus();
    verifyTab.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await wait(() => verifyTab.getAttribute('aria-selected') === 'true', 'verification tab activated');
    await wait(() => !document.querySelector('.operation-bar button').disabled, 'verification action enabled');
    document.querySelector('.operation-bar button').click();
    await wait(() => document.querySelector('.result-column').textContent.includes('CMS'), 'UI verification');
    checks.push('native UI verification and actual CMS/digest verification');
    await invoke('remove_pe_signature', { filePath: config.file });
    if ((await invoke('list_pe_signatures', { filePath: config.file })).length !== 0) throw new Error('Native signature removal failed');
    checks.push('native signature removal on a disposable file copy');
    await invoke('finish_desktop_smoke', { success: true, checks, error: null });
  } catch (error) {
    await invoke('finish_desktop_smoke', { success: false, checks, error: String(error?.stack ?? error) });
  }
}
