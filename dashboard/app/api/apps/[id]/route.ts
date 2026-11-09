import { NextResponse } from "next/server";
import { pool, query } from "@/lib/db";
import { authenticate } from "@/lib/auth";
import { getClientIp, logAuditEvent } from "@/lib/audit";
import {
  isMissingAppsSchema,
  parseAppPayload,
  validateDisableAllowed,
  validateSlugUpdate,
} from "@/lib/apps";
import { reloadAppsCache } from "@/lib/ml-engine";

const SCHEMA_ERROR =
  "Falta aplicar migraciones (waf_apps / waf_app_domains). Ejecutá ./scripts/apply-migrations.sh";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function PATCH(
  request: Request,
  { params }: { params: { id: string } }
) {
  const ip = getClientIp(request);
  const auth = await authenticate(request, { requireAdmin: true });

  if (!auth.ok) {
    await logAuditEvent("app.update", "blocked", {
      ip,
      details: { reason: "admin_required", app_id: params.id },
    });
    return auth.response;
  }

  const actor = { userid: String(auth.user.userid), username: auth.user.username };

  if (!UUID_RE.test(params.id)) {
    await logAuditEvent("app.update", "failure", {
      user: actor,
      ip,
      details: { reason: "invalid_app_id", app_id: params.id },
    });
    return NextResponse.json({ error: "ID de aplicación inválido" }, { status: 400 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    await logAuditEvent("app.update", "failure", {
      user: actor,
      ip,
      details: { reason: "invalid_json", app_id: params.id },
    });
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const parsed = parseAppPayload(body, { partial: true });
  if (!parsed.ok) {
    await logAuditEvent("app.update", "failure", {
      user: actor,
      ip,
      details: { reason: "validation_error", app_id: params.id, error: parsed.error },
    });
    return NextResponse.json({ error: parsed.error }, { status: 400 });
  }

  const data = parsed.value;
  if (
    data.slug === undefined &&
    data.name === undefined &&
    data.domains === undefined &&
    data.backend_url === undefined &&
    data.enabled === undefined
  ) {
    return NextResponse.json({ error: "No hay cambios para aplicar" }, { status: 400 });
  }

  try {
    const existingResult = await query(
      `SELECT a.id::text AS id, a.slug, a.name, a.domain, a.backend_url, a.enabled,
              COALESCE(
                array_agg(d.domain ORDER BY d.id) FILTER (WHERE d.domain IS NOT NULL),
                '{}'::text[]
              ) AS domains
       FROM waf_apps a
       LEFT JOIN waf_app_domains d ON d.app_id = a.id
       WHERE a.id = $1
       GROUP BY a.id`,
      [params.id]
    );

    if (existingResult.rows.length === 0) {
      await logAuditEvent("app.update", "failure", {
        user: actor,
        ip,
        details: { reason: "not_found", app_id: params.id },
      });
      return NextResponse.json({ error: "Aplicación no encontrada" }, { status: 404 });
    }

    const existing = existingResult.rows[0];
    const existingDomains: string[] =
      Array.isArray(existing.domains) && existing.domains.length > 0
        ? existing.domains
        : [existing.domain];

    const nextDomains = data.domains ?? existingDomains;
    const nextDomain = data.domains ? data.domains[0] : existing.domain;

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const locked = await client.query(
        `SELECT slug, enabled FROM waf_apps WHERE id = $1 FOR UPDATE`,
        [params.id]
      );
      if (locked.rows.length === 0) {
        await client.query("ROLLBACK");
        await logAuditEvent("app.update", "failure", {
          user: actor,
          ip,
          details: { reason: "not_found", app_id: params.id },
        });
        return NextResponse.json({ error: "Aplicación no encontrada" }, { status: 404 });
      }

      const lockedApp = locked.rows[0];
      const slugCheck = validateSlugUpdate(lockedApp.slug, data.slug);
      if (!slugCheck.ok) {
        await client.query("ROLLBACK");
        await logAuditEvent("app.update", "failure", {
          user: actor,
          ip,
          details: { reason: "slug_immutable", app_id: params.id },
        });
        return NextResponse.json({ error: slugCheck.error }, { status: 400 });
      }

      if (data.enabled === false && lockedApp.enabled) {
        const enabledRows = await client.query(
          `SELECT id FROM waf_apps WHERE enabled = true FOR UPDATE`
        );
        const disableCheck = validateDisableAllowed(
          Boolean(lockedApp.enabled),
          enabledRows.rows.length
        );
        if (!disableCheck.ok) {
          await client.query("ROLLBACK");
          await logAuditEvent("app.update", "failure", {
            user: actor,
            ip,
            details: { reason: "last_enabled_app", app_id: params.id },
          });
          return NextResponse.json({ error: disableCheck.error }, { status: 409 });
        }
      }

      if (data.domains) {
        const conflict = await client.query(
          `SELECT domain FROM waf_app_domains
           WHERE domain = ANY($1::text[]) AND app_id <> $2
           UNION
           SELECT domain FROM waf_apps
           WHERE domain = ANY($1::text[]) AND id <> $2`,
          [data.domains, params.id]
        );
        if (conflict.rows.length > 0) {
          await client.query("ROLLBACK");
          await logAuditEvent("app.update", "failure", {
            user: actor,
            ip,
            details: {
              reason: "domain_conflict",
              app_id: params.id,
              domains: conflict.rows.map((row) => row.domain),
            },
          });
          return NextResponse.json(
            { error: "Uno o más dominios ya están registrados" },
            { status: 409 }
          );
        }

        await client.query("DELETE FROM waf_app_domains WHERE app_id = $1", [params.id]);
        await client.query(
          `INSERT INTO waf_app_domains (app_id, domain)
           SELECT $1, unnest($2::text[])`,
          [params.id, data.domains]
        );
      }

      const updated = await client.query(
        `UPDATE waf_apps
         SET name = $2,
             domain = $3,
             backend_url = $4,
             enabled = $5,
             updated_at = NOW()
         WHERE id = $1
         RETURNING id::text AS id, slug, name, domain, backend_url, enabled, created_at, updated_at`,
        [
          params.id,
          data.name ?? existing.name,
          nextDomain,
          data.backend_url ?? existing.backend_url,
          data.enabled ?? lockedApp.enabled,
        ]
      );

      await client.query("COMMIT");

      const app = updated.rows[0];
      const action =
        data.enabled === false && Boolean(lockedApp.enabled) ? "app.disable" : "app.update";
      const changed: string[] = [];
      if (data.name !== undefined && data.name !== existing.name) changed.push("name");
      if (data.domains !== undefined) changed.push("domains");
      if (data.backend_url !== undefined && data.backend_url !== existing.backend_url) {
        changed.push("backend_url");
      }
      if (data.enabled !== undefined && data.enabled !== Boolean(lockedApp.enabled)) {
        changed.push("enabled");
      }

      await logAuditEvent(action, "success", {
        user: actor,
        ip,
        details: {
          app_id: app.id,
          slug: app.slug,
          changed,
          domains: nextDomains,
          backend_url: app.backend_url,
          enabled: Boolean(app.enabled),
        },
      });

      const reload = await reloadAppsCache(auth.token);
      if (!reload.ok) {
        console.error("reload_apps failed after app.update:", reload.status, reload.error);
        await logAuditEvent("app.reload", "failure", {
          user: actor,
          ip,
          details: { app_id: app.id, status: reload.status, error: reload.error },
        });
      }

      return NextResponse.json({
        app: { ...app, enabled: Boolean(app.enabled), domains: nextDomains },
      });
    } catch (error: any) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  } catch (error: any) {
    if (isMissingAppsSchema(error)) {
      return NextResponse.json({ error: SCHEMA_ERROR }, { status: 503 });
    }
    if (error?.code === "23505") {
      await logAuditEvent("app.update", "failure", {
        user: actor,
        ip,
        details: { reason: "unique_conflict", app_id: params.id },
      });
      return NextResponse.json(
        { error: "El slug o alguno de los dominios ya existen" },
        { status: 409 }
      );
    }

    console.error("Apps API Error:", error);
    await logAuditEvent("app.update", "failure", {
      user: actor,
      ip,
      details: { reason: "internal_error", app_id: params.id },
    });
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  }
}
