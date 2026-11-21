import { invoke, isTauri } from '@tauri-apps/api/core';
import type { Policy, Snapshot, Status } from './types';
export async function snapshot(): Promise<Snapshot> {
  if (!isTauri()) return { status: { connected: false, active: false, platform: 'preview', version: '1.0.0', report: { applied: 0, unsupported: [] }, capabilities: [], error: '瀏覽器預覽不具備原生攔截能力，請啟動桌面應用程式。' }, policy: { rules: [], exclusions: [] }, flows: [], events: [], observation_error: null, data_dir: '' };
  return invoke('get_snapshot');
}
export async function savePolicy(policy: Policy): Promise<Status> { return invoke('save_policy', { policy }); }
export async function control(action: 'pause' | 'resume'): Promise<Status> { return invoke('agent_control', { action }); }
export async function importPolicy(text: string): Promise<Status> { return invoke('import_policy', { text }); }
export async function importFeed(text: string): Promise<Status> { return invoke('import_feed', { text }); }
export async function exportPolicy(): Promise<string> { return invoke('export_policy'); }
export async function clearEvents(): Promise<void> { return invoke('clear_events'); }
export async function autostart(enabled: boolean): Promise<void> { return invoke('set_autostart', { enabled }); }
export async function autostartEnabled(): Promise<boolean> { return isTauri() ? invoke('autostart_enabled') : false; }
export async function launchAgent(): Promise<Status> { return invoke('launch_agent'); }
export async function updateFeed(): Promise<Status> { return invoke('update_feed'); }
