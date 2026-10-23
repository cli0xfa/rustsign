import { describe, expect, it } from 'vitest';
import {
  initialWorkspace,
  workspaceReducer,
  unixToLocalInput,
  localInputToUnix,
} from './workspace';
import { certificateValidity, canUsePrivateKey } from './certificates';
import { certificate } from '@/test/fixtures';

describe('workspace state', () => {
  it('keeps drafts while switching file tasks and rejects stale file data', () => {
    let state = workspaceReducer(initialWorkspace, {
      type: 'sign',
      patch: { description: 'release' },
    });
    state = workspaceReducer(state, { type: 'file', path: 'first.exe', revision: 1 });
    state = workspaceReducer(state, {
      type: 'result',
      revision: 1,
      result: { tone: 'success', title: 'wb.signSuccess' },
    });
    state = workspaceReducer(state, { type: 'file', path: 'second.exe', revision: 2 });
    state = workspaceReducer(state, { type: 'signatures', revision: 1, error: 'old read failed' });
    state = workspaceReducer(state, {
      type: 'result',
      revision: 1,
      result: { tone: 'error', title: 'old' },
    });
    expect(state.file.path).toBe('second.exe');
    expect(state.file.error).toBeNull();
    expect(state.result).toBeNull();
    expect(state.sign.description).toBe('release');
    expect(workspaceReducer(state, { type: 'tab', tab: 'verify' }).sign.description).toBe(
      'release',
    );
  });
  it('does not allow a target change during an operation', () => {
    const state = workspaceReducer(
      { ...initialWorkspace, operation: 'sign' },
      { type: 'file', path: 'other.exe', revision: 1 },
    );
    expect(state.file.path).toBe('');
  });
  it('does not overwrite edited drafts with late defaults', () => {
    let state = workspaceReducer(initialWorkspace, { type: 'sign', patch: { digest: 'sha512' } });
    state = workspaceReducer(state, { type: 'sign', defaults: true, patch: { digest: 'sha1' } });
    state = workspaceReducer(state, {
      type: 'tsa',
      patch: { fixedDatetime: '2026-10-24T10:11:12' },
    });
    state = workspaceReducer(state, { type: 'tsa', defaults: true, patch: { fixedDatetime: '' } });
    expect(state.sign.digest).toBe('sha512');
    expect(state.tsa.fixedDatetime).toBe('2026-10-24T10:11:12');
  });
});
describe('certificate metadata', () => {
  it('distinguishes missing data, expiry and unavailable keys', () => {
    expect(certificateValidity({ ...certificate, not_after_secs: null })).toBe('unknown');
    expect(certificateValidity({ ...certificate, file_readable: false })).toBe('unreadable');
    expect(certificateValidity({ ...certificate, not_after_secs: 1 }, 100)).toBe('notYetValid');
    expect(
      certificateValidity({ ...certificate, not_before_secs: 0, not_after_secs: 1 }, 100),
    ).toBe('expired');
    expect(canUsePrivateKey({ ...certificate, has_private_key: false })).toBe(false);
    expect(canUsePrivateKey({ ...certificate, has_private_key: null })).toBe(true);
  });
});
describe('local TSA time', () => {
  it('round trips local time including seconds without using UTC wall time', () => {
    const local = '2026-10-24T17:18:19';
    const seconds = localInputToUnix(local)!;
    expect(unixToLocalInput(seconds)).toBe(local);
    expect(new Date(seconds * 1000).getHours()).toBe(17);
  });
  it('rejects missing and invalid custom time', () => {
    expect(localInputToUnix('')).toBeNull();
    expect(localInputToUnix('invalid')).toBeNull();
  });
});
