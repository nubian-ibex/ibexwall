import type { Finding } from '../gen/contracts';

export type ClientId = 'claude-code' | 'opencode' | 'vscode';
export const CLIENTS: ClientId[] = ['claude-code', 'opencode', 'vscode'];
export type Preset = 'read' | 'plan' | 'propose';
export const PRESETS: Preset[] = ['read', 'plan', 'propose'];

/** What to paste to connect a client on this machine (stdio): the same text
 * `ibexctl mcp config` prints. */
export function snippet(client: ClientId): { where: string; text: string } {
  switch (client) {
    case 'claude-code':
      return {
        where: '.mcp.json',
        text: JSON.stringify(
          {
            mcpServers: {
              ibexwall: { type: 'stdio', command: 'ibexwall-mcp', args: ['--client', client] },
            },
          },
          null,
          2,
        ),
      };
    case 'opencode':
      return {
        where: 'opencode.json',
        text: JSON.stringify(
          {
            mcp: {
              ibexwall: {
                type: 'local',
                command: ['ibexwall-mcp', '--client', client],
                enabled: true,
              },
            },
          },
          null,
          2,
        ),
      };
    case 'vscode':
      return {
        where: '.vscode/mcp.json',
        text: JSON.stringify(
          {
            servers: {
              ibexwall: { type: 'stdio', command: 'ibexwall-mcp', args: ['--client', client] },
            },
          },
          null,
          2,
        ),
      };
  }
}

export interface RemoteState {
  enabled: boolean;
  listen: string;
  /** SHA-256 of the certificate the server presents; empty when there is none. */
  fingerprint: string;
  tokens: { id: string; name: string; client: string; preset: string; expires: string }[];
}

/** The transport and the tokens, from what the plugin reports. */
export function remoteState(findings: Finding[]): RemoteState {
  const http = findings.find((f) => f.id === 'assistant.http');
  return {
    enabled: http?.args?.enabled === 'true',
    listen: http?.args?.listen ?? '127.0.0.1:8765',
    fingerprint: findings.find((f) => f.id === 'assistant.tls')?.args?.fingerprint ?? '',
    tokens: findings
      .filter((f) => f.id.startsWith('assistant.token.'))
      .map((f) => ({
        id: f.args?.id ?? '',
        name: f.args?.name ?? '',
        client: f.args?.client ?? '',
        preset: f.args?.preset ?? '',
        expires: f.args?.expires ?? '',
      })),
  };
}

/** Names or addresses typed with commas or spaces, as the plugin takes them. */
export function splitHosts(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((h) => h.trim())
    .filter(Boolean);
}

export function remoteUrl(listen: string): string {
  return `https://${listen}/mcp`;
}
