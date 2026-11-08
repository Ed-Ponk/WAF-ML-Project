"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  AlertCircle,
  CheckCircle2,
  Loader2,
  Pencil,
  Plus,
  Power,
  PowerOff,
  Server,
  X,
} from "lucide-react";

interface AppRecord {
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

interface FormState {
  slug: string;
  name: string;
  domains: string;
  backend_url: string;
  enabled: boolean;
}

const EMPTY_FORM: FormState = {
  slug: "",
  name: "",
  domains: "",
  backend_url: "",
  enabled: true,
};

export default function AppManagement() {
  const [apps, setApps] = useState<AppRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [formOpen, setFormOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);

  const loadApps = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("/dashboard/api/apps");
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.error || "No se pudo cargar la lista de aplicaciones");
      }
      setApps(Array.isArray(data.apps) ? data.apps : []);
    } catch (err: any) {
      setError(err.message || "Error de red al cargar las aplicaciones");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadApps();
  }, [loadApps]);

  const activeCount = apps.filter((app) => app.enabled).length;
  const editingApp = editingId ? apps.find((app) => app.id === editingId) : undefined;
  const isLastEnabled = Boolean(editingApp?.enabled && activeCount === 1);

  const openCreate = () => {
    setEditingId(null);
    setForm(EMPTY_FORM);
    setFormError(null);
    setFormOpen(true);
  };

  const openEdit = (app: AppRecord) => {
    setEditingId(app.id);
    setForm({
      slug: app.slug,
      name: app.name,
      domains: (app.domains.length > 0 ? app.domains : [app.domain]).join(", "),
      backend_url: app.backend_url,
      enabled: app.enabled,
    });
    setFormError(null);
    setFormOpen(true);
  };

  const closeForm = () => {
    if (saving) return;
    setFormOpen(false);
    setFormError(null);
  };

  const updateField = (field: keyof FormState, value: string | boolean) => {
    setForm((current) => ({ ...current, [field]: value }));
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setFormError(null);
    setSuccess(null);

    const domains = form.domains
      .split(/[\s,]+/)
      .map((domain) => domain.trim())
      .filter(Boolean);

    const payload: Record<string, unknown> = {
      name: form.name.trim(),
      domains,
      backend_url: form.backend_url.trim(),
      enabled: form.enabled,
    };
    if (!editingId) {
      payload.slug = form.slug.trim();
    }

    try {
      const response = await fetch(
        editingId ? `/dashboard/api/apps/${editingId}` : "/dashboard/api/apps",
        {
          method: editingId ? "PATCH" : "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }
      );
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.error || "No se pudo guardar la aplicación");
      }
      setSuccess(editingId ? "Aplicación actualizada." : "Aplicación creada.");
      setFormOpen(false);
      setForm(EMPTY_FORM);
      setEditingId(null);
      await loadApps();
    } catch (err: any) {
      setFormError(err.message || "Error de red al guardar");
    } finally {
      setSaving(false);
    }
  };

  const toggleEnabled = async (app: AppRecord) => {
    if (
      app.enabled &&
      !window.confirm(
        `¿Deshabilitar "${app.name}"? El tráfico dejará de enrutarse cuando el motor recargue la caché.`
      )
    ) {
      return;
    }

    setBusyId(app.id);
    setError(null);
    setSuccess(null);
    try {
      const response = await fetch(`/dashboard/api/apps/${app.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !app.enabled }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.error || "No se pudo cambiar el estado");
      }
      setSuccess(app.enabled ? "Aplicación deshabilitada." : "Aplicación habilitada.");
      await loadApps();
    } catch (err: any) {
      setError(err.message || "Error de red al cambiar el estado");
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <p className="text-sm font-semibold text-white">
              {activeCount} {activeCount === 1 ? "aplicación activa" : "aplicaciones activas"}
            </p>
            <p className="text-[11px] text-slate-500">
              {apps.length} registradas en total
            </p>
          </div>
        </div>
        <button
          onClick={openCreate}
          className="inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold text-cyan-300 hover:text-cyan-200 bg-cyan-500/10 border border-cyan-500/20 transition"
        >
          <Plus className="w-4 h-4" />
          Nueva aplicación
        </button>
      </div>

      {error && (
        <div className="flex items-start gap-2 rounded-lg border border-red-900/40 bg-red-950/20 px-3 py-2 text-xs text-red-300">
          <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}
      {success && (
        <div className="flex items-start gap-2 rounded-lg border border-emerald-900/40 bg-emerald-950/20 px-3 py-2 text-xs text-emerald-300">
          <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{success}</span>
        </div>
      )}

      {formOpen && (
        <form
          onSubmit={handleSubmit}
          className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3"
        >
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              {editingId ? "Editar aplicación" : "Registrar aplicación"}
            </h3>
            <button
              type="button"
              onClick={closeForm}
              className="text-slate-500 hover:text-white transition"
              aria-label="Cerrar formulario"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="block">
              <span className="text-[11px] text-slate-400">Nombre</span>
              <input
                value={form.name}
                onChange={(event) => updateField("name", event.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                placeholder="PYME Atel"
                required
              />
            </label>
            <label className="block">
              <span className="text-[11px] text-slate-400">Slug</span>
              <input
                value={form.slug}
                onChange={(event) => updateField("slug", event.target.value)}
                disabled={Boolean(editingId)}
                className={`mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500 ${
                  editingId ? "cursor-not-allowed opacity-60" : ""
                }`}
                placeholder="pyme"
                required
              />
              {editingId && (
                <span className="mt-1 block text-[10px] text-slate-500">
                  El slug no se puede modificar.
                </span>
              )}
            </label>
            <label className="block md:col-span-2">
              <span className="text-[11px] text-slate-400">
                Dominios (separados por coma o espacio)
              </span>
              <input
                value={form.domains}
                onChange={(event) => updateField("domains", event.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                placeholder="pyme.waf.local, www.pyme.waf.local"
                required
              />
            </label>
            <label className="block md:col-span-2">
              <span className="text-[11px] text-slate-400">Backend URL</span>
              <input
                value={form.backend_url}
                onChange={(event) => updateField("backend_url", event.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                placeholder="http://pyme-php-backend:80"
                required
              />
            </label>
          </div>

          <label className="flex items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(event) => updateField("enabled", event.target.checked)}
              disabled={isLastEnabled}
              className="h-4 w-4 rounded border-slate-700 bg-slate-950 disabled:opacity-60"
            />
            Habilitada
            {isLastEnabled && (
              <span className="text-[10px] text-slate-500">
                No se puede deshabilitar la última aplicación activa.
              </span>
            )}
          </label>

          {formError && (
            <div className="flex items-start gap-2 rounded-lg border border-red-900/40 bg-red-950/20 px-3 py-2 text-xs text-red-300">
              <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
              <span>{formError}</span>
            </div>
          )}

          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={closeForm}
              disabled={saving}
              className="px-3 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-white transition"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-60 transition"
            >
              {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              {editingId ? "Guardar cambios" : "Registrar"}
            </button>
          </div>
        </form>
      )}

      <div className="rounded-xl border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-wider">
              <tr>
                <th className="px-4 py-3 font-semibold">Aplicación</th>
                <th className="px-4 py-3 font-semibold">Dominios</th>
                <th className="px-4 py-3 font-semibold">Backend</th>
                <th className="px-4 py-3 font-semibold">Estado</th>
                <th className="px-4 py-3 font-semibold text-right">Acciones</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {loading && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                    <Loader2 className="w-4 h-4 animate-spin inline-block mr-2" />
                    Cargando aplicaciones...
                  </td>
                </tr>
              )}
              {!loading && apps.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                    No hay aplicaciones registradas.
                  </td>
                </tr>
              )}
              {!loading &&
                apps.map((app) => (
                  <tr key={app.id} className="hover:bg-slate-900/40">
                    <td className="px-4 py-3">
                      <p className="font-semibold text-slate-100">{app.name}</p>
                      <p className="text-[11px] text-slate-500 font-mono">{app.slug}</p>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {(app.domains.length > 0 ? app.domains : [app.domain]).map((domain) => (
                          <span
                            key={domain}
                            className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-mono text-slate-300"
                          >
                            {domain}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-slate-400">
                      {app.backend_url}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ${
                          app.enabled
                            ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                            : "bg-slate-800 text-slate-400 border border-slate-700"
                        }`}
                      >
                        {app.enabled ? "Activa" : "Deshabilitada"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => openEdit(app)}
                          className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-[11px] font-semibold text-slate-300 hover:text-white hover:bg-slate-800 transition"
                        >
                          <Pencil className="w-3.5 h-3.5" />
                          Editar
                        </button>
                        <button
                          onClick={() => toggleEnabled(app)}
                          disabled={busyId === app.id || (app.enabled && activeCount === 1)}
                          className={`inline-flex items-center gap-1 rounded-lg px-2 py-1 text-[11px] font-semibold transition disabled:opacity-60 ${
                            app.enabled
                              ? "text-amber-400 hover:text-amber-300 hover:bg-amber-950/20"
                              : "text-emerald-400 hover:text-emerald-300 hover:bg-emerald-950/20"
                          }`}
                        >
                          {busyId === app.id ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : app.enabled ? (
                            <PowerOff className="w-3.5 h-3.5" />
                          ) : (
                            <Power className="w-3.5 h-3.5" />
                          )}
                          {app.enabled ? "Deshabilitar" : "Habilitar"}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
