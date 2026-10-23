interface TauriDragDropPayload {
  type: 'enter' | 'over' | 'drop' | 'leave' | 'cancel';
  paths?: string[];
}

interface TauriWindowHandle {
  minimize?: () => Promise<void>;
  maximize?: () => Promise<void>;
  unmaximize?: () => Promise<void>;
  toggleMaximize?: () => Promise<void>;
  isMaximized?: () => Promise<boolean>;
  isFocused?: () => Promise<boolean>;
  setTitle?: (title: string) => Promise<void>;
  startDragging?: () => Promise<void>;
  onResized?: (handler: () => void) => Promise<() => void>;
  onFocusChanged?: (handler: (event: { payload: boolean }) => void) => Promise<() => void>;
  onScaleChanged?: (handler: () => void) => Promise<() => void>;
  onDragDropEvent(
    handler: (event: { payload?: TauriDragDropPayload }) => void,
  ): Promise<() => void>;
}

interface TauriNamespace {
  getCurrentWindow?: () => TauriWindowHandle | null;
}

interface TauriGlobal {
  app?: { getVersion: () => Promise<string> };
  event?: {
    listen: <T>(name: string, handler: (event: { payload: T }) => void) => Promise<() => void>;
  };
  core: {
    invoke<T>(command: string, args?: Record<string, unknown>): Promise<T>;
  };
  window?: TauriNamespace;
  webviewWindow?: TauriNamespace;
  webview?: TauriNamespace;
}

declare global {
  interface Window {
    __TAURI__?: TauriGlobal;
  }
}

export {};
