import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi, test, expect, beforeEach } from 'vitest';
import App from './App';
import * as api from './api';
import type { Snapshot } from './types';
vi.mock('./api');
const empty: Snapshot = { status: { connected: false, active: false, platform: 'windows', version: '1.0.0', report: { applied: 0, unsupported: [] }, capabilities: [], error: 'agent offline' }, policy: { rules: [], exclusions: [] }, flows: [], events: [], observation_error: null, data_dir: 'test' };
beforeEach(() => { vi.resetAllMocks(); vi.mocked(api.snapshot).mockResolvedValue(structuredClone(empty)); vi.mocked(api.autostartEnabled).mockResolvedValue(false); });
test('disconnected agent never displays active protection', async () => {
  render(<App/>); expect(await screen.findByText('防護服務未連線')).toBeInTheDocument();
  expect(screen.queryByText('原生防護已啟用')).not.toBeInTheDocument();
});
test('starting protection reports success only after the service responds', async () => {
  const started = { ...empty.status, connected: true, active: true, error: null };
  let confirmStartup!: (status: Snapshot['status']) => void;
  vi.mocked(api.launchAgent).mockImplementation(() => new Promise(resolve => {
    confirmStartup = resolve;
  }));
  const user = userEvent.setup();
  render(<App/>);
  await user.click(await screen.findByRole('button', { name: '啟動服務' }));
  expect(screen.queryByText('原生防護已啟用')).not.toBeInTheDocument();
  confirmStartup(started);
  expect(await screen.findByText('原生防護已啟用')).toBeInTheDocument();
});
test('rule save errors remain visible and retain editor input', async () => {
  vi.mocked(api.savePolicy).mockRejectedValue('無效的 IP 位址'); const user = userEvent.setup(); render(<App/>);
  await user.click(await screen.findByRole('button', { name: '規則管理' })); await user.click(screen.getByRole('button', { name: '新增規則' }));
  await user.type(screen.getByLabelText('規則名稱'), '背景程式封鎖'); await user.type(screen.getByLabelText('目的地'), 'invalid-ip');
  await user.click(screen.getByRole('button', { name: '儲存規則' }));
  expect(await screen.findByText('無效的 IP 位址')).toBeInTheDocument(); expect(screen.getByLabelText('目的地')).toHaveValue('invalid-ip');
});
test('unknown connection hostname is explicitly shown as unknown', async () => {
  vi.mocked(api.snapshot).mockResolvedValue({ ...empty, flows: [{ remote_ip: '192.0.2.7', remote_port: 443, protocol: 6, program: null, pid: 5, hostname: null, observed_at: 100, state: 'tcp:5' }] });
  const user = userEvent.setup(); render(<App/>); await user.click(await screen.findByRole('button', { name: '連線活動' }));
  await waitFor(() => expect(screen.getByText('192.0.2.7')).toBeInTheDocument()); expect(screen.getByText('網域未知')).toBeInTheDocument();
});
