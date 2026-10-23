import { useState, useEffect, useRef, useCallback } from 'react';
import { classifyDroppedFile } from '@/lib/utils';

interface UseDragDropOptions {
  onPeFile: (filePath: string) => void;
  onCertFile: (filePath: string) => void;
  onUnsupported: (filePath: string) => void;
}

function getCurrentTauriWindowHandle() {
  const namespaces = [
    window.__TAURI__?.window,
    window.__TAURI__?.webviewWindow,
    window.__TAURI__?.webview,
  ];
  for (const ns of namespaces) {
    const win = ns?.getCurrentWindow?.();
    if (win?.onDragDropEvent) return win;
  }
  return null;
}

export function useDragDrop({ onPeFile, onCertFile, onUnsupported }: UseDragDropOptions) {
  const [isDragging, setIsDragging] = useState(false);
  const dragDepthRef = useRef(0);

  const handleDroppedPath = useCallback(
    (filePath: string) => {
      const kind = classifyDroppedFile(filePath);
      if (kind === 'pe') onPeFile(filePath);
      else if (kind === 'cert') onCertFile(filePath);
      else onUnsupported(filePath);
    },
    [onPeFile, onCertFile, onUnsupported],
  );

  useEffect(() => {
    // DOM-level drag events
    const onDragEnter = (e: DragEvent) => {
      if (!e.dataTransfer?.types?.includes('Files')) return;
      e.preventDefault();
      dragDepthRef.current += 1;
      setIsDragging(true);
    };

    const onDragOver = (e: DragEvent) => {
      if (!e.dataTransfer?.types?.includes('Files')) return;
      e.preventDefault();
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
    };

    const onDragLeave = (e: DragEvent) => {
      if (!e.dataTransfer?.types?.includes('Files')) return;
      e.preventDefault();
      dragDepthRef.current = Math.max(0, dragDepthRef.current - 1);
      if (dragDepthRef.current === 0) setIsDragging(false);
    };

    const onDrop = (e: DragEvent) => {
      if (!e.dataTransfer?.types?.includes('Files')) return;
      e.preventDefault();
      setIsDragging(false);
      dragDepthRef.current = 0;

      const files = Array.from(e.dataTransfer?.files ?? []) as (File & { path?: string })[];
      const filePath = files.find((f) => typeof f.path === 'string' && f.path.length > 0)?.path;
      if (filePath) handleDroppedPath(filePath);
    };

    const onBlur = () => {
      setIsDragging(false);
      dragDepthRef.current = 0;
    };

    window.addEventListener('dragenter', onDragEnter);
    window.addEventListener('dragover', onDragOver);
    window.addEventListener('dragleave', onDragLeave);
    window.addEventListener('drop', onDrop);
    window.addEventListener('blur', onBlur);

    // Tauri native drag-drop
    let cleanup: (() => void) | undefined;
    const handle = getCurrentTauriWindowHandle();
    if (handle) {
      handle
        .onDragDropEvent((event) => {
          const payload = event.payload;
          if (!payload) return;

          if (payload.type === 'enter' || payload.type === 'over') {
            setIsDragging(true);
            return;
          }
          setIsDragging(false);

          if (payload.type === 'drop' && payload.paths?.[0]) {
            handleDroppedPath(payload.paths[0]);
          }
        })
        .then((unlisten: unknown) => {
          cleanup = unlisten as () => void;
        })
        .catch(() => {
          /* ignore */
        });
    }

    return () => {
      window.removeEventListener('dragenter', onDragEnter);
      window.removeEventListener('dragover', onDragOver);
      window.removeEventListener('dragleave', onDragLeave);
      window.removeEventListener('drop', onDrop);
      window.removeEventListener('blur', onBlur);
      cleanup?.();
    };
  }, [handleDroppedPath]);

  return { isDragging };
}
