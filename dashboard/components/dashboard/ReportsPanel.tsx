"use client";

import React, { useState } from "react";
import {
  FileText,
  Download,
  Loader2,
  FileSpreadsheet,
  File,
  CheckCircle2,
  AlertCircle,
  Activity,
} from "lucide-react";

interface ReportCardProps {
  title: string;
  description: string;
  icon: React.ReactNode;
  endpoint: string;
  formats: { label: string; format: string; icon: React.ReactNode }[];
  dateFrom?: string;
  dateTo?: string;
  extraParams?: Record<string, string>;
}

function ReportCard({ title, description, icon, endpoint, formats, dateFrom, dateTo, extraParams }: ReportCardProps) {
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleDownload = async (format: string, dateFrom?: string, dateTo?: string) => {
    setLoading(format);
    setError(null);
    setSuccess(null);

    const params = new URLSearchParams({ format });
    if (dateFrom) params.set("date_from", dateFrom);
    if (dateTo) params.set("date_to", dateTo);
    if (extraParams) {
      for (const [k, v] of Object.entries(extraParams)) {
        params.set(k, v);
      }
    }

    try {
      const res = await fetch(`${endpoint}?${params.toString()}`, {
        credentials: "include",
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Error desconocido" }));
        throw new Error(err.error || `HTTP ${res.status}`);
      }

      const blob = await res.blob();
      const ext = format === "pdf" ? "pdf" : "csv";
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `reporte-${title.toLowerCase().replace(/\s+/g, "-")}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      setSuccess(`Descargado como ${format.toUpperCase()}`);
      setTimeout(() => setSuccess(null), 3000);
    } catch (err: any) {
      setError(err.message);
      setTimeout(() => setError(null), 5000);
    } finally {
      setLoading(null);
    }
  };

  return (
    <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-all duration-200">
      <div className="flex items-start gap-4">
        <div className="p-3 rounded-lg bg-cyan-500/10 text-cyan-400 shrink-0">
          {icon}
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-semibold text-white mb-1">{title}</h3>
          <p className="text-xs text-slate-400 leading-relaxed">{description}</p>

          <div className="flex flex-wrap gap-2 mt-4">
            {formats.map((fmt) => (
              <button
                key={fmt.format}
                onClick={() => handleDownload(fmt.format, dateFrom, dateTo)}
                disabled={loading !== null}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition duration-150 disabled:opacity-50 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/50"
              >
                {loading === fmt.format ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  fmt.icon
                )}
                {loading === fmt.format ? "Generando..." : fmt.label}
              </button>
            ))}
          </div>

          {success && (
            <div className="flex items-center gap-1.5 mt-3 text-xs text-emerald-400">
              <CheckCircle2 className="w-3.5 h-3.5" />
              {success}
            </div>
          )}
          {error && (
            <div className="flex items-center gap-1.5 mt-3 text-xs text-red-400">
              <AlertCircle className="w-3.5 h-3.5" />
              {error}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ReportsPanel() {
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [modelWindow, setModelWindow] = useState("7d");

  const reports: ReportCardProps[] = [
    {
      title: "Resumen Diario de Tráfico",
      description:
        "Volumen de requests, tasa de bloqueos y distribución por tipo de ataque (SQLi, XSS, RCE) de los últimos 30 días.",
      icon: <FileText className="w-5 h-5" />,
      endpoint: "/dashboard/api/reports/daily",
      formats: [
        { label: "CSV", format: "csv", icon: <FileSpreadsheet className="w-3.5 h-3.5" /> },
        { label: "PDF", format: "pdf", icon: <File className="w-3.5 h-3.5" /> },
      ],
    },
    {
      title: "Alertas de Seguridad",
      description:
        "Listado detallado de los últimos 100 eventos bloqueados con score ML, IP origen y URL completa.",
      icon: <FileText className="w-5 h-5" />,
      endpoint: "/dashboard/api/reports/alerts",
      formats: [
        { label: "CSV", format: "csv", icon: <FileSpreadsheet className="w-3.5 h-3.5" /> },
        { label: "PDF", format: "pdf", icon: <File className="w-3.5 h-3.5" /> },
      ],
    },
      {
        title: "Reporte Completo",
        description:
          "Informe ejecutivo consolidado con resumen, métricas de rendimiento, últimas alertas y matriz de confusión contra baselines.",
        icon: <File className="w-5 h-5" />,
        endpoint: "/dashboard/api/reports/comprehensive",
        formats: [
          { label: "PDF", format: "pdf", icon: <File className="w-3.5 h-3.5" /> },
        ],
      },
      {
        title: "Salud del Modelo",
        description:
          "Distribución de scores, FPR/Recall vs benchmark, recall por CWE, tendencia de zonas ALLOW/LOG/BLOCK y recomendación automática de reentrenamiento. Ventana móvil de 7 o 30 días.",
        icon: <Activity className="w-5 h-5" />,
        endpoint: "/dashboard/api/reports/model-health",
        formats: [
          { label: "JSON", format: "json", icon: <FileText className="w-3.5 h-3.5" /> },
          { label: "PDF", format: "pdf", icon: <File className="w-3.5 h-3.5" /> },
        ],
        extraParams: { window: modelWindow },
      },
    ];

  return (
    <div className="space-y-6 animate-fade-in pb-10">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white uppercase">
          Reportes e Informes
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Genere reportes descargables en formato CSV y PDF para análisis,
          auditoría y documentación de tesis.
        </p>
      </div>

      {/* Date Range Filter */}
      <div className="flex flex-wrap gap-3 items-end bg-slate-900/40 border border-slate-800 rounded-xl p-4">
        <div className="flex flex-col gap-1">
          <label className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Desde</label>
          <input
            type="date"
            value={dateFrom}
            onChange={(e) => setDateFrom(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none [color-scheme:dark]"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Hasta</label>
          <input
            type="date"
            value={dateTo}
            onChange={(e) => setDateTo(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none [color-scheme:dark]"
          />
        </div>
        {(dateFrom || dateTo) && (
          <button
            onClick={() => { setDateFrom(""); setDateTo(""); }}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/50 transition"
          >
            Limpiar filtro
          </button>
        )}
        {/* Window selector for model-health */}
        <div className="flex flex-col gap-1">
          <label className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Ventana Salud</label>
          <div className="flex gap-1">
            <button
              onClick={() => setModelWindow("7d")}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
                modelWindow === "7d"
                  ? "bg-cyan-500/20 border-cyan-500/40 text-cyan-300"
                  : "bg-slate-800 border-slate-700/50 text-slate-400 hover:text-white hover:bg-slate-700"
              }`}
            >
              7 días
            </button>
            <button
              onClick={() => setModelWindow("30d")}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
                modelWindow === "30d"
                  ? "bg-cyan-500/20 border-cyan-500/40 text-cyan-300"
                  : "bg-slate-800 border-slate-700/50 text-slate-400 hover:text-white hover:bg-slate-700"
              }`}
            >
              30 días
            </button>
          </div>
        </div>
        <span className="text-[10px] text-slate-600 ml-auto self-center">
          {dateFrom || dateTo
            ? `Filtrando desde ${dateFrom || "—"} hasta ${dateTo || "—"}`
            : "Sin filtro de fecha — todos los datos"}
        </span>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {reports.map((r, i) => (
          <ReportCard key={i} {...r} dateFrom={dateFrom} dateTo={dateTo} />
        ))}
      </div>

      {/* Info box about data availability */}
      <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5">
        <h4 className="text-sm font-semibold text-slate-300 mb-2 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-cyan-400" />
          Nota sobre disponibilidad de datos
        </h4>
        <ul className="text-xs text-slate-500 space-y-1 list-disc list-inside">
          <li>Los reportes requieren datos en PostgreSQL (waf_events, waf_daily_summary, waf_baselines).</li>
          <li>Si un reporte devuelve &quot;Sin datos&quot;, ejecute el benchmark o espere a que ml-engine registre eventos.</li>
          <li>El Reporte Completo incluye la matriz de confusión solo si existen baselines configurados.</li>
        </ul>
      </div>
    </div>
  );
}
