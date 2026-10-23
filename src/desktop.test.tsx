import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import App from './App';
import { installBridge, tsaStatus } from './test/fixtures';

describe('desktop shell', () => {
  it('reveals the themed committed shell even when hidden-window animation frames are suspended', async () => {
    const bridge = installBridge();
    localStorage.setItem('rustsign-theme', 'light');
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation(() => 0);
    render(<App />);
    await waitFor(() =>
      expect(bridge.calls).toContainEqual({
        command: 'complete_startup',
        args: { theme: 'light' },
      }),
    );
    expect(document.documentElement).not.toHaveClass('dark');
    expect(screen.getByRole('heading', { name: '文件工作台' })).toBeVisible();
  });

  it('reports failed startup instead of silently discarding the native error', async () => {
    installBridge({
      complete_startup: () => {
        throw new Error('Native reveal failed');
      },
    });
    render(<App />);
    expect(await screen.findByText('工作台启动失败，请重新加载或退出后重试。')).toBeVisible();
  });

  it('uses the same file picker for the menu and shortcut and suppresses shortcuts in dialogs', async () => {
    const bridge = installBridge();
    const user = userEvent.setup();
    render(<App />);
    fireEvent.keyDown(window, { key: 'o', ctrlKey: true });
    await screen.findByLabelText('完整路径');
    expect(bridge.calls.filter((call) => call.command === 'open_file_dialog')).toHaveLength(1);
    fireEvent.keyDown(window, { key: 'I', ctrlKey: true, shiftKey: true });
    await screen.findByRole('dialog');
    fireEvent.keyDown(window, { key: 'o', ctrlKey: true });
    expect(bridge.calls.filter((call) => call.command === 'open_file_dialog')).toHaveLength(2);
    await user.click(screen.getByRole('button', { name: '取消' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await user.click(screen.getByRole('menuitem', { name: '文件' }));
    await user.click(screen.getByRole('menuitem', { name: /打开 PE 文件/ }));
    await waitFor(() =>
      expect(bridge.calls.filter((call) => call.command === 'open_file_dialog')).toHaveLength(3),
    );
  });

  it('returns menu focus with Escape and synchronizes the window title with navigation', async () => {
    installBridge();
    const user = userEvent.setup();
    render(<App />);
    const file = screen.getByRole('menuitem', { name: '文件' });
    file.focus();
    await user.keyboard('{ArrowDown}');
    expect(await screen.findByRole('menuitem', { name: /打开 PE 文件/ })).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(file).toHaveFocus();
    fireEvent.keyDown(window, { key: '2', ctrlKey: true });
    await waitFor(() => expect(document.title).toBe('证书库 — RustSign'));
  });

  it('honors a busy result from the backend for tasks outside the current page', async () => {
    const bridge = installBridge({ request_app_close: () => 'busy' });
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: '关闭窗口' }));
    expect(await screen.findByText('任务正在执行，请等待任务完成后退出。')).toBeVisible();
    expect(bridge.calls).toContainEqual({
      command: 'request_app_close',
      args: { confirmTsaStop: false },
    });
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  });

  it('requires TSA confirmation and supports cancelling before a confirmed exit', async () => {
    const bridge = installBridge({
      get_tsa_server_status: () => ({ ...tsaStatus, running: true }),
      request_app_close: (args) => (args.confirmTsaStop ? 'closing' : 'confirm-tsa'),
    });
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: '关闭窗口' }));
    await screen.findByRole('alertdialog');
    expect(screen.getByRole('button', { name: '取消' })).toHaveFocus();
    await user.click(screen.getByRole('button', { name: '取消' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(bridge.calls.filter((call) => call.command === 'request_app_close')).toHaveLength(1);
    await user.click(screen.getByRole('button', { name: '关闭窗口' }));
    await user.click(await screen.findByRole('button', { name: '确认执行' }));
    await waitFor(() =>
      expect(bridge.calls).toContainEqual({
        command: 'request_app_close',
        args: { confirmTsaStop: true },
      }),
    );
  });
});
