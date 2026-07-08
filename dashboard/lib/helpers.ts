/**
 * ══════════════════════════════════════════════════════════════════
 * Helpers — shared utility functions for the dashboard
 * ══════════════════════════════════════════════════════════════════
 */

/**
 * Anonymize an IP address by replacing the last octet with 0.
 *
 * IPv4: 192.168.1.100  → 192.168.1.0
 * IPv6: keeps first 80 bits (20 hex chars), zeros the rest.
 * Invalid/missing: returns original value.
 */
export function anonymizeIP(ip: string | null | undefined): string {
  if (!ip) return ip ?? "";

  // IPv4
  const ipv4Match = ip.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$/);
  if (ipv4Match) {
    return `${ipv4Match[1]}.0`;
  }

  // IPv6 — keep first 80 bits (20 hex chars), zero the rest
  //   Simplificación: replace last group with ::
  //   Formato típico: 2001:db8:85a3::8a2e:370:7334 → 2001:db8:85a3::
  const ipv6Short = ip.replace(/::ffff:/, ""); // handle IPv4-mapped IPv6
  if (ipv6Short.includes(":") && !ipv6Short.startsWith("::")) {
    const parts = ipv6Short.split(":");
    // Keep first 3 groups (48 bits), zero rest
    const kept = parts.slice(0, 3).join(":");
    return `${kept}::`;
  }

  // Not an IP we can parse — return as-is
  return ip;
}
