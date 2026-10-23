import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import App from './App';
import { WorkspaceProvider, useWorkspace } from '@/contexts/WorkspaceContext';
import { certificate, installBridge, signature } from '@/test/fixtures';
import type { SignatureInfo } from '@/types';

describe('workbench flows', () => {
  it('preserves file and all three drafts across navigation', async () => {
    installBridge();
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: '选择 PE 文件' }));
    await user.selectOptions(screen.getByLabelText('签名证书'), certificate.id);
    await user.click(screen.getByText('高级选项'));
    await user.type(screen.getByLabelText('程序描述'), 'Release 42');
    await user.click(screen.getByRole('button', { name: '证书库' }));
    await user.click(screen.getByRole('button', { name: '生成测试证书' }));
    await user.type(screen.getByLabelText('组织名称 O（可选）'), 'Acme');
    await user.click(screen.getByRole('button', { name: '时间戳服务' }));
    await user.type(screen.getByLabelText('服务名称'), 'Development TSA');
    await user.click(screen.getByRole('button', { name: '文件工作台' }));
    await user.click(screen.getByText('高级选项'));
    expect(screen.getByLabelText('程序描述')).toHaveValue('Release 42');
    expect(screen.getByLabelText('签名证书')).toHaveValue(certificate.id);
    expect(screen.getByLabelText('完整路径')).toHaveTextContent('C:\\build\\client.exe');
    await user.click(screen.getByRole('button', { name: '证书库' }));
    await user.click(screen.getByRole('button', { name: '生成测试证书' }));
    expect(screen.getByLabelText('组织名称 O（可选）')).toHaveValue('Acme');
    await user.click(screen.getByRole('button', { name: '时间戳服务' }));
    expect(screen.getByLabelText('服务名称')).toHaveValue('Development TSA');
  });
  it('verification works without a signing certificate', async () => {
    const bridge = installBridge({}, []);
    const user = userEvent.setup();
    render(<App />);
    expect(screen.getByRole('button', { name: '开始签名' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: '选择 PE 文件' }));
    await screen.findByLabelText('完整路径');
    await user.click(screen.getByRole('tab', { name: '验证' }));
    const verify = screen.getByRole('button', { name: '验证签名' });
    await waitFor(() => expect(verify).toBeEnabled());
    await user.click(verify);
    await waitFor(
      () => expect(bridge.calls.some((call) => call.command === 'verify_pe_signature')).toBe(true),
      { timeout: 5000 },
    );
    await waitFor(
      () =>
        expect(document.querySelector('.result-announcement')).toHaveTextContent(
          'CMS 签名与文件摘要校验通过',
        ),
      { timeout: 5000 },
    );
    expect(bridge.calls.some((call) => call.command === 'verify_pe_signature')).toBe(true);
  });
  it('shows a loading failure instead of an empty certificate library and can retry', async () => {
    let fail = true;
    installBridge({
      list_certificates: () => {
        if (fail) throw { category: 'io', message: 'disk unavailable' };
        return [certificate];
      },
    });
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: '证书库' }));
    expect(await screen.findByRole('heading', { name: '无法读取证书库' })).toBeInTheDocument();
    expect(screen.queryByText('暂无证书')).not.toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole('button', { name: '重试' }));
    expect(await screen.findByText(certificate.subject)).toBeInTheDocument();
  });
  it('requires destructive confirmation, focuses cancel, and restores focus', async () => {
    const bridge = installBridge({ list_pe_signatures: () => [signature] });
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: '选择 PE 文件' }));
    await user.selectOptions(screen.getByLabelText('签名证书'), certificate.id);
    const sign = screen.getByRole('button', { name: '开始签名' });
    await waitFor(() => expect(sign).toBeEnabled());
    await user.click(sign);
    const cancel = await screen.findByRole('button', { name: '取消' });
    expect(cancel).toHaveFocus();
    expect(bridge.calls.some((call) => call.command === 'sign_pe_file')).toBe(false);
    await user.click(cancel);
    await waitFor(() => expect(sign).toHaveFocus());
    await user.click(sign);
    await user.click(await screen.findByRole('button', { name: '确认执行' }));
    await waitFor(
      () => expect(bridge.calls.some((call) => call.command === 'sign_pe_file')).toBe(true),
      { timeout: 5000 },
    );
    await waitFor(
      () =>
        expect(document.querySelector('.result-announcement')).toHaveTextContent(
          '签名已写入原文件',
        ),
      { timeout: 5000 },
    );
  });
  it('clears selection when search changes so hidden rows cannot be deleted', async () => {
    installBridge();
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: '证书库' }));
    await user.click(await screen.findByLabelText('全选'));
    expect(screen.getByRole('button', { name: '删除所选' })).toBeEnabled();
    await user.type(screen.getByLabelText('搜索名称、颁发者或指纹'), 'no match');
    expect(screen.getByRole('button', { name: '删除所选' })).toBeDisabled();
    expect(screen.getByText('没有匹配的证书')).toBeInTheDocument();
  });
  it('refreshes the shared certificate source after import', async () => {
    installBridge({}, []);
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: '前往证书库' }));
    await screen.findByText('暂无证书');
    await user.click(screen.getAllByRole('button', { name: '导入证书' })[0]);
    await user.click(await screen.findByRole('button', { name: '导入证书' }));
    await screen.findByText(certificate.subject);
    await user.click(screen.getByRole('button', { name: '返回文件工作台' }));
    expect(screen.getByLabelText('签名证书')).toHaveTextContent(certificate.subject);
  });
});

function Harness() {
  const { state, openFile, runFileOperation } = useWorkspace();
  return (
    <>
      <button onClick={() => openFile('first.exe')}>first</button>
      <button onClick={() => openFile('second.exe')}>second</button>
      <button
        onClick={() => {
          void runFileOperation('sign', async () => {
            await window.__TAURI__!.core.invoke('slow_write');
            return { tone: 'success', title: 'done' };
          });
        }}
      >
        write
      </button>
      <output data-testid="file-state">
        {state.file.path}|{state.file.signatures.map((sig) => sig.subject).join(',')}|
        {state.operation}
      </output>
    </>
  );
}
describe('async isolation', () => {
  it('ignores old file responses that arrive after the current file', async () => {
    const reads: Record<string, (value: SignatureInfo[]) => void> = {};
    installBridge({
      list_pe_signatures: (args) =>
        new Promise<SignatureInfo[]>((resolve) => {
          reads[String(args.filePath)] = resolve;
        }),
    });
    render(
      <WorkspaceProvider>
        <Harness />
      </WorkspaceProvider>,
    );
    fireEvent.click(screen.getByText('first'));
    fireEvent.click(screen.getByText('second'));
    await act(async () => {
      reads['second.exe']([{ ...signature, subject: 'current' }]);
    });
    await act(async () => {
      reads['first.exe']([{ ...signature, subject: 'stale' }]);
    });
    expect(screen.getByTestId('file-state')).toHaveTextContent('second.exe|current');
    expect(screen.getByTestId('file-state')).not.toHaveTextContent('stale');
  });
  it('serializes writes and refuses a target change until completion', async () => {
    let finish: () => void = () => {};
    const bridge = installBridge({
      slow_write: () =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }),
    });
    render(
      <WorkspaceProvider>
        <Harness />
      </WorkspaceProvider>,
    );
    fireEvent.click(screen.getByText('first'));
    await waitFor(() => expect(screen.getByTestId('file-state')).toHaveTextContent('first.exe'));
    fireEvent.click(screen.getByText('write'));
    fireEvent.click(screen.getByText('write'));
    fireEvent.click(screen.getByText('second'));
    expect(bridge.calls.filter((call) => call.command === 'slow_write')).toHaveLength(1);
    expect(screen.getByTestId('file-state')).toHaveTextContent('first.exe');
    await act(async () => {
      finish();
    });
    fireEvent.click(screen.getByText('second'));
    expect(screen.getByTestId('file-state')).toHaveTextContent('second.exe');
  });
});
