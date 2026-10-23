import { normalizeError } from './errors';

export type CloseState = 'busy' | 'confirm-tsa' | 'closing';
export type CaptionAction = 'enter' | 'leave' | 'down' | 'up' | 'click';
export interface ChromeRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

export function desktopWindow() {
  return window.__TAURI__?.window?.getCurrentWindow?.() ?? null;
}

export async function desktopInvoke<T>(
  command: string,
  args: Record<string, unknown>,
): Promise<T | undefined> {
  if (!window.__TAURI__?.core) return undefined;
  try {
    return await window.__TAURI__.core.invoke<T>(command, args);
  } catch (error) {
    throw normalizeError(error);
  }
}

export function completeStartup(theme: 'dark' | 'light') {
  return desktopInvoke<void>('complete_startup', { theme });
}

export async function requestAppClose(confirmTsaStop = false) {
  return desktopInvoke<CloseState>('request_app_close', { confirmTsaStop });
}

export function syncWindowChrome(maximizeRect: ChromeRect, blocked: boolean) {
  return desktopInvoke<void>('sync_window_chrome', { maximizeRect, blocked });
}

export async function listenDesktop<T>(
  name: string,
  handler: (payload: T) => void,
): Promise<() => void> {
  if (window.__TAURI__?.event) {
    return window.__TAURI__.event.listen<T>(name, (event) => handler(event.payload));
  }
  const listener = (event: Event) => handler((event as CustomEvent<T>).detail);
  window.addEventListener(name, listener);
  return () => window.removeEventListener(name, listener);
}

export async function windowAction(
  action: 'minimize' | 'maximize' | 'restore' | 'toggle' | 'move' | 'resize',
) {
  const current = desktopWindow();
  switch (action) {
    case 'minimize':
      return current?.minimize?.();
    case 'maximize':
      return current?.maximize?.();
    case 'restore':
      return current?.unmaximize?.();
    case 'toggle':
      return current?.toggleMaximize?.();
    default:
      return desktopInvoke<void>('window_system_action', { action });
  }
}

export async function desktopVersion() {
  if (window.__TAURI__?.app) return window.__TAURI__.app.getVersion();
  return '0.3.0';
}
