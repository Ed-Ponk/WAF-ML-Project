/**
 * ══════════════════════════════════════════════════════════════════
 * Apps — normalización y validación del registro de aplicaciones.
 *
 * Este módulo es la capa de validación del dashboard. El ml-engine
 * revalida el backend_url al cargar la caché y al hacer proxy (defensa
 * en profundidad): acá no resolvemos DNS porque el dashboard no está
 * conectado a todas las redes donde viven los backends de las apps.
 * ══════════════════════════════════════════════════════════════════
 */

const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const DOMAIN_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

const INTERNAL_HOST_DENYLIST = new Set([
  "localhost",
  "database",
  "ml-engine",
  "waf-dashboard",
  "mysql",
  "vpn",
  "proxy",
  "certbot",
  "waf-db",
  "waf-ml-engine",
  "waf-pyme-db",
  "waf-vpn",
  "waf-proxy",
  "host.docker.internal",
  "gateway.docker.internal",
  "metadata.google.internal",
]);

export interface AppRecord {
  id: string;
  slug: string;
  name: string;
  domain: string;
  domains: string[];
  backend_url: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AppPayload {
  slug?: string;
  name?: string;
  domains?: string[];
  backend_url?: string;
  enabled?: boolean;
}

export type ValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

export function normalizeSlug(value: unknown): string {
  return String(value ?? "").trim().toLowerCase();
}

export function normalizeDomain(value: unknown): string {
  return String(value ?? "").trim().toLowerCase().replace(/\.+$/, "");
}

export function normalizeBackendUrl(value: unknown): string {
  return String(value ?? "").trim().replace(/\/+$/, "");
}

export function validateSlug(raw: unknown): ValidationResult<string> {
  const slug = normalizeSlug(raw);
  if (!slug) return { ok: false, error: "El slug es obligatorio" };
  if (slug.length > 63) return { ok: false, error: "El slug no puede superar 63 caracteres" };
  if (!SLUG_RE.test(slug)) {
    return {
      ok: false,
      error: "El slug solo admite minúsculas, números y guiones (sin guiones al inicio/fin ni consecutivos)",
    };
  }
  return { ok: true, value: slug };
}

export function validateDomain(raw: unknown): ValidationResult<string> {
  const domain = normalizeDomain(raw);
  if (!domain) return { ok: false, error: "El dominio es obligatorio" };
  if (domain.length > 253) return { ok: false, error: "El dominio no puede superar 253 caracteres" };
  if (domain.includes("://") || domain.includes("/") || domain.includes(":") || domain.includes(" ")) {
    return { ok: false, error: "El dominio debe ser un hostname, sin esquema, puerto ni ruta" };
  }
  if (INTERNAL_HOST_DENYLIST.has(domain)) {
    return { ok: false, error: `El dominio '${domain}' es un nombre interno del stack` };
  }
  for (const label of domain.split(".")) {
    if (!DOMAIN_LABEL_RE.test(label)) {
      return { ok: false, error: `Dominio inválido: '${domain}'` };
    }
  }
  return { ok: true, value: domain };
}

function parseIpv4(host: string): number[] | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    octets.push(n);
  }
  return octets;
}

function isBlockedIpv4(octets: number[]): boolean {
  const [a, b] = octets;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // 127.0.0.0/8
  if (a === 169 && b === 254) return true; // 169.254.0.0/16
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT)
  if (a >= 224) return true; // multicast + reserved
  return false;
}

function isBlockedIpv6(host: string): boolean {
  const h = host.toLowerCase();
  if (h.startsWith("::")) return true; // unspecified, loopback, IPv4-compatible/mapped
  if (h.includes(":ffff:")) return true; // IPv4-mapped in expanded form
  if (h.startsWith("fe80:")) return true; // link-local
  if (h.startsWith("fc") || h.startsWith("fd")) return true; // unique local
  if (h.startsWith("ff")) return true; // multicast
  if (h.startsWith("2001:db8:")) return true; // documentation
  return false;
}

function isBlockedHostLiteral(host: string): boolean {
  const normalized = host.toLowerCase().replace(/\.+$/, "");
  const octets = parseIpv4(normalized);
  if (octets) return isBlockedIpv4(octets);
  if (normalized.includes(":")) return isBlockedIpv6(normalized);
  return false;
}

export function validateBackendUrl(raw: unknown): ValidationResult<string> {
  const value = normalizeBackendUrl(raw);
  if (!value) return { ok: false, error: "El backend_url es obligatorio" };

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return { ok: false, error: "backend_url inválida" };
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, error: "backend_url solo admite http:// o https://" };
  }
  if (url.username || url.password) {
    return { ok: false, error: "backend_url no puede incluir credenciales" };
  }
  if (url.search || url.hash) {
    return { ok: false, error: "backend_url no puede incluir query string ni fragmento" };
  }

  const host = url.hostname
    .toLowerCase()
    .replace(/^\[/, "")
    .replace(/\]$/, "")
    .replace(/\.+$/, "");
  if (!host) return { ok: false, error: "backend_url sin host" };
  if (INTERNAL_HOST_DENYLIST.has(host)) {
    return { ok: false, error: `backend_url apunta a un servicio interno no permitido: '${host}'` };
  }
  if (isBlockedHostLiteral(host)) {
    return {
      ok: false,
      error: "backend_url apunta a loopback, link-local, rango privado o dirección reservada",
    };
  }

  const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, error: "backend_url con puerto inválido" };
  }

  return { ok: true, value };
}

export function validateSlugUpdate(
  currentSlug: string,
  nextSlug: string | undefined
): ValidationResult<true> {
  if (nextSlug !== undefined && nextSlug !== currentSlug) {
    return { ok: false, error: "El slug no se puede modificar" };
  }
  return { ok: true, value: true };
}

export function validateDisableAllowed(
  currentlyEnabled: boolean,
  enabledCount: number
): ValidationResult<true> {
  if (currentlyEnabled && enabledCount <= 1) {
    return { ok: false, error: "No se puede deshabilitar la última aplicación activa" };
  }
  return { ok: true, value: true };
}

export function parseAppPayload(
  body: unknown,
  options: { partial?: boolean } = {}
): ValidationResult<AppPayload> {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, error: "Payload inválido" };
  }

  const input = body as Record<string, unknown>;
  const partial = options.partial === true;
  const out: AppPayload = {};

  if (!partial || input.slug !== undefined) {
    const result = validateSlug(input.slug);
    if (!result.ok) return result;
    out.slug = result.value;
  }

  if (!partial || input.name !== undefined) {
    const name = String(input.name ?? "").trim();
    if (!name) return { ok: false, error: "El nombre es obligatorio" };
    if (name.length > 120) return { ok: false, error: "El nombre no puede superar 120 caracteres" };
    out.name = name;
  }

  if (!partial || input.domains !== undefined || input.domain !== undefined) {
    const rawDomains = Array.isArray(input.domains)
      ? input.domains
      : input.domain !== undefined
        ? [input.domain]
        : [];
    if (rawDomains.length === 0) {
      return { ok: false, error: "Debés registrar al menos un dominio" };
    }
    const domains: string[] = [];
    for (const rawDomain of rawDomains) {
      const result = validateDomain(rawDomain);
      if (!result.ok) return result;
      if (!domains.includes(result.value)) domains.push(result.value);
    }
    out.domains = domains;
  }

  if (!partial || input.backend_url !== undefined) {
    const result = validateBackendUrl(input.backend_url);
    if (!result.ok) return result;
    out.backend_url = result.value;
  }

  if (input.enabled !== undefined) {
    if (typeof input.enabled !== "boolean") {
      return { ok: false, error: "enabled debe ser booleano" };
    }
    out.enabled = input.enabled;
  }

  return { ok: true, value: out };
}

export function isMissingAppsSchema(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && (error as { code?: string }).code === "42P01");
}
