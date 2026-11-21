export type Action = 'allow' | 'block' | 'ask';
export type Target = { kind: 'any' } | { kind: 'ip' | 'network' | 'domain' | 'subdomains'; value: string };
export type Rule = { id: string; name: string; target: Target; action: Action; enabled: boolean; program: string | null; protocol: number | null; port: number | null; expires_at: number | null; source: string | null };
export type Policy = { rules: Rule[]; exclusions: string[] };
export type Status = { connected: boolean; active: boolean; platform: string; version: string; report: { applied: number; unsupported: string[] }; capabilities: { name: string; available: boolean; detail: string }[]; error: string | null };
export type Flow = { remote_ip: string; remote_port: number; protocol: number; program: string | null; pid: number | null; hostname: string | null; observed_at: number; state: string };
export type Event = { at: number; kind: string; message: string };
export type Snapshot = { status: Status; policy: Policy; flows: Flow[]; events: Event[]; observation_error: string | null; data_dir: string };
