import { NextResponse } from "next/server";
import { pool, query } from "@/lib/db";
import { authenticate } from "@/lib/auth";
import { getClientIp, logAuditEvent } from "@/lib/audit";
import { isMissingAppsSchema, parseAppPayload } from "@/lib/apps";
import { reloadAppsCache } from "@/lib/ml-engine";

const SCHEMA_ERROR =
  "Falta aplicar migraciones (waf_apps / waf_app_domains). Ejecutá ./scripts/apply-migrations.sh";

export async function GET(request: Request) {
  const auth = await authenticate(request, { requireAdmin: true });
  if (!auth.ok) return auth.response;

  try {
    const result = await query(
      `SELECT a.id::text AS id, a.slug, a.name, a.domain, a.backend_url, a.enabled,
              a.created_at, a.updated_at,
              COALESCE(
                array_agg(d.domain ORDER BY d.id) FILTER (WHERE d.domain IS NOT NULL),
                '{}'::text[]
              ) AS domains
       FROM waf_apps a
       LEFT JOIN waf_app_domains d ON d.app_id = a.id
       GROUP BY a.id
       ORDER BY a.name ASC`
    );

    const apps = result.rows.map((row) => ({
      ...row,
      enabled: Boolean(row.enabled),
      domains: Array.isArray(row.domains) ? row.domains : [],
    }));

    return NextResponse.json({
      apps,
      active_count: apps.filter((app) => app.enabled).length,
    });
  } catch (error) {
    if (isMissingAppsSchema(error)) {
      return NextResponse.json({ error: SCHEMA_ERROR }, { status: 503 });
    }
    console.error("Apps API Error:", error);
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  }
}

export async function POST(request: Request) {
  const ip = getClientIp(request);
  const auth = await authenticate(request, { requireAdmin: true });

  if (!auth.ok) {
    await logAuditEvent("app.create", "blocked", {
      ip,
      details: { reason: "admin_required" },
    });
    return auth.response;
  }

  const actor = { userid: String(auth.user.userid), username: auth.user.username };

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    await logAuditEvent("app.create", "failure", {
      user: actor,
      ip,
      details: { reason: "invalid_json" },
    });
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const parsed = parseAppPayload(body);
  if (!parsed.ok) {
    await logAuditEvent("app.create", "failure", {
      user: actor,
      ip,
      details: { reason: "validation_error", error: parsed.error },
    });
    return NextResponse.json({ error: parsed.error }, { status: 400 });
  }

  const slug = parsed.value.slug!;
  const name = parsed.value.name!;
  const domains = parsed.value.domains!;
  const backendUrl = parsed.value.backend_url!;
  const enabled = parsed.value.enabled ?? true;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const conflict = await client.query(
      `SELECT domain FROM waf_app_domains WHERE domain = ANY($1::text[])
       UNION
       SELECT domain FROM waf_apps WHERE domain = ANY($1::text[])`,
      [domains]
    );
    if (conflict.rows.length > 0) {
      await client.query("ROLLBACK");
      await logAuditEvent("app.create", "failure", {
        user: actor,
        ip,
        details: {
          reason: "domain_conflict",
          domains: conflict.rows.map((row) => row.domain),
        },
      });
      return NextResponse.json(
        { error: "Uno o más dominios ya están registrados" },
        { status: 409 }
      );
    }

    const inserted = await client.query(
      `INSERT INTO waf_apps (slug, name, domain, backend_url, enabled)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id::text AS id, slug, name, domain, backend_url, enabled, created_at, updated_at`,
      [slug, name, domains[0], backendUrl, enabled]
    );
    const app = inserted.rows[0];

    await client.query(
      `INSERT INTO waf_app_domains (app_id, domain)
       SELECT $1, unnest($2::text[])`,
      [app.id, domains]
    );

    await client.query("COMMIT");

    await logAuditEvent("app.create", "success", {
      user: actor,
      ip,
      details: {
        app_id: app.id,
        slug: app.slug,
        domains,
        backend_url: app.backend_url,
        enabled: Boolean(app.enabled),
      },
    });

    const reload = await reloadAppsCache(auth.token);
    if (!reload.ok) {
      console.error("reload_apps failed after app.create:", reload.status, reload.error);
      await logAuditEvent("app.reload", "failure", {
        user: actor,
        ip,
        details: { app_id: app.id, status: reload.status, error: reload.error },
      });
    }

    return NextResponse.json(
      { app: { ...app, enabled: Boolean(app.enabled), domains } },
      { status: 201 }
    );
  } catch (error: any) {
    await client.query("ROLLBACK").catch(() => undefined);

    if (isMissingAppsSchema(error)) {
      return NextResponse.json({ error: SCHEMA_ERROR }, { status: 503 });
    }
    if (error?.code === "23505") {
      await logAuditEvent("app.create", "failure", {
        user: actor,
        ip,
        details: { reason: "unique_conflict", slug, domains },
      });
      return NextResponse.json(
        { error: "El slug o alguno de los dominios ya existen" },
        { status: 409 }
      );
    }

    console.error("Apps API Error:", error);
    await logAuditEvent("app.create", "failure", {
      user: actor,
      ip,
      details: { reason: "internal_error" },
    });
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  } finally {
    client.release();
  }
}
