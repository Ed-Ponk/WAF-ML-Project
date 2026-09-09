import { query } from "@/lib/db";

export type AuditResult = "success" | "failure" | "blocked";

export interface AuditActor {
  userid?: string | null;
  username?: string | null;
}

/**
 * IP confiable del cliente. X-Real-IP es seteado incondicionalmente por nginx
 * a $remote_addr y es la fuente autoritativa. X-Forwarded-For puede arrastrar
 * valores del cliente (nginx hace append), por eso solo es fallback (último
 * elemento) cuando falta X-Real-IP.
 */
export function getClientIp(request: Request): string {
  const realIp = request.headers.get("x-real-ip");
  if (realIp && realIp.trim()) {
    return realIp.trim();
  }
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded && forwarded.trim()) {
    const parts = forwarded.split(",");
    return parts[parts.length - 1].trim();
  }
  return "unknown";
}

function parseIp(ip: string | null | undefined): string | null {
  if (!ip) return null;
  if (/^[\da-fA-F.:/]+$/.test(ip)) return ip;
  return null;
}

/**
 * Persiste un evento de auditoría de acción administrativa.
 *
 * La auditoría es best-effort: NUNCA relanza. Si el INSERT falla (tabla caída,
 * DB inalcanzable), la operación principal del caller debe completarse igual;
 * el fallo queda en console.error.
 *
 * Detalles sensibles: el caller es responsable de NO incluir password, tokens,
 * cookies ni headers de autorización. details se serializa tal cual.
 */
export async function logAuditEvent<T extends Record<string, unknown>>(
  action: string,
  result: AuditResult,
  opts: {
    user?: AuditActor | null;
    ip?: string | null;
    details?: T;
  } = {}
): Promise<void> {
  try {
    await query(
      `INSERT INTO waf_audit_log (user_id, username, action, result, ip_address, details)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        opts.user?.userid ?? null,
        opts.user?.username ?? null,
        action,
        result,
        parseIp(opts.ip),
        JSON.stringify(opts.details ?? {}),
      ]
    );
  } catch (err) {
    console.error("Audit log write failed:", err);
  }
}