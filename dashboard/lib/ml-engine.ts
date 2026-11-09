const ML_ENGINE_URL = process.env.ML_ENGINE_URL || "http://ml-engine:8000";
const RELOAD_TIMEOUT_MS = 5000;

export interface ReloadAppsResult {
  ok: boolean;
  status: number | null;
  error?: string;
}

/**
 * Recarga la caché de apps/dominios del ml-engine reenviando el JWT del admin.
 * Nunca lanza: el caller decide si el fallo debe registrarse o ignorarse.
 */
export async function reloadAppsCache(token: string): Promise<ReloadAppsResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), RELOAD_TIMEOUT_MS);

  try {
    const res = await fetch(`${ML_ENGINE_URL}/reload_apps`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal,
    });

    if (res.ok) {
      return { ok: true, status: res.status };
    }

    let detail = "";
    try {
      const body = await res.json();
      detail = String(body?.detail || "");
    } catch {
      // Respuesta no JSON: usar el status text.
    }

    return { ok: false, status: res.status, error: detail || res.statusText };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, status: null, error: message };
  } finally {
    clearTimeout(timeout);
  }
}
