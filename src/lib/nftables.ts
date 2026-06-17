import type { FirewallPolicy } from './database.types';
// @ts-expect-error - pure JS module shared with the Node server (no .d.ts)
import * as impl from './firewall-compile.mjs';

/** Minimal device shape used to resolve device-ID / group matches to IPs. */
export interface DeviceRef {
  id: string;
  hostname?: string;
  ip_address?: string | null;
  tags?: string[];
}

/**
 * The firewall compilers live in `firewall-compile.mjs` so the management
 * server (plain ESM) and this UI can share one implementation. These typed
 * wrappers keep the rest of the app type-checked.
 */
export function compileNftables(policies: FirewallPolicy[], devices: DeviceRef[] = []): string {
  return impl.compileNftables(policies, devices);
}

export function compileWindowsFirewall(policies: FirewallPolicy[], devices: DeviceRef[] = []): string {
  return impl.compileWindowsFirewall(policies, devices);
}

export function validatePolicies(policies: FirewallPolicy[], devices: DeviceRef[] = []): string[] {
  return impl.validatePolicies(policies, devices);
}
