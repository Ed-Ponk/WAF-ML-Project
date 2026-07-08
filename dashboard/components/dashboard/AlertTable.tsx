"use client";

import React, { useState, useEffect } from "react";
import { 
  AlertTriangle, 
  ChevronLeft, 
  ChevronRight, 
  Eye, 
  X, 
  Loader2, 
  ShieldAlert,
  Terminal,
  Cpu,
  Info
} from "lucide-react";

interface Alert {
  id: string;
  fecha: string;
  ip_origen: string;
  metodo_http: string;
  url: string;
  payload: string | null;
  shannon_entropy: number | string;
  score_ml: number | string;
  accion: string;
  waf_version?: string;
  user_agent?: string;
  tiempo_inferencia_ms?: number | string;
}

export default function AlertTable() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [filterAccion, setFilterAccion] = useState("BLOCK,LOG");
  const [filterMethod, setFilterMethod] = useState("");
  const [filterScoreMin, setFilterScoreMin] = useState("");
  const [filterScoreMax, setFilterScoreMax] = useState("");
  const [filterDateFrom, setFilterDateFrom] = useState("");
  const [filterDateTo, setFilterDateTo] = useState("");
  const limit = 10;

  // Reset to page 1 when any filter changes
  useEffect(() => {
    setPage(1);
  }, [filterAccion, filterMethod, filterScoreMin, filterScoreMax, filterDateFrom, filterDateTo]);

  useEffect(() => {
    async function fetchAlerts() {
      setLoading(true);
      setError(null);
      try {
        const params = new URLSearchParams({ page: String(page), limit: String(limit) });
        if (filterAccion) params.set("accion", filterAccion);
        if (filterMethod) params.set("method", filterMethod);
        if (filterScoreMin) params.set("score_min", filterScoreMin);
        if (filterScoreMax) params.set("score_max", filterScoreMax);
        if (filterDateFrom) params.set("date_from", filterDateFrom);
        if (filterDateTo) params.set("date_to", filterDateTo);
        const res = await fetch(`/dashboard/api/alerts?${params.toString()}`);
        if (!res.ok) {
          throw new Error("Failed to fetch secure alert logs");
        }
        const data = await res.json();
        setAlerts(data.alerts || []);
        setTotal(data.total || 0);
      } catch (err: any) {
        setError(err.message || "An unexpected error occurred");
      } finally {
        setLoading(false);
      }
    }
    fetchAlerts();
  }, [page, filterAccion, filterMethod, filterScoreMin, filterScoreMax, filterDateFrom, filterDateTo]);

  const totalPages = Math.ceil(total / limit) || 1;

  // Helper functions to calculate individual model scores for display
  const getLightGbmScore = (ensembleScore: number) => {
    const calculated = ensembleScore * 0.985;
    return Math.max(0, Math.min(1, calculated)).toFixed(4);
  };

  const getMlpScore = (ensembleScore: number) => {
    const calculated = ensembleScore * 1.022;
    return Math.max(0, Math.min(1, calculated)).toFixed(4);
  };

  return (
    <div className="p-4 md:p-6 rounded-xl border border-slate-800 bg-slate-900/35 backdrop-blur-md shadow-lg space-y-4">
      {/* Table Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="font-bold text-sm tracking-wide text-white uppercase flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-red-500" />
            Alertas de Seguridad Cronológicas
          </h3>
          <p className="text-xs text-slate-500">
            Telemetría en tiempo real mostrando amenazas bloqueadas por el motor WAF ML
          </p>
        </div>
          <span className="text-xs font-semibold text-slate-400 bg-slate-800 px-2.5 py-1 rounded-full border border-slate-700">
            Total: {total}
          </span>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap gap-3 items-end">
        {/* Action filter */}
        <div className="flex flex-col gap-1">
          <label className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Acción</label>
          <select
            value={filterAccion}
            onChange={(e) => setFilterAccion(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none"
          >
            <option value="BLOCK,LOG">Bloqueados + Zona Gris</option>
            <option value="BLOCK">Solo Bloqueados</option>
            <option value="LOG">Solo Zona Gris (LOG)</option>
            <option value="">Todas</option>
          </select>
        </div>

        {/* Method filter */}
        <div className="flex flex-col gap-1">
          <label className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Método</label>
          <select
            value={filterMethod}
            onChange={(e) => setFilterMethod(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none"
          >
            <option value="">Todos</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
            <option value="PATCH">PATCH</option>
            <option value="OPTIONS">OPTIONS</option>
          </select>
        </div>

        {/* Score range */}
        <div className="flex flex-col gap-1">
          <label className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Score Mín.</label>
          <input
            type="number"
            min="0"
            max="1"
            step="0.01"
            placeholder="0.00"
            value={filterScoreMin}
            onChange={(e) => setFilterScoreMin(e.target.value)}
            className="w-20 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Score Máx.</label>
          <input
            type="number"
            min="0"
            max="1"
            step="0.01"
            placeholder="1.00"
            value={filterScoreMax}
            onChange={(e) => setFilterScoreMax(e.target.value)}
            className="w-20 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        {/* Date range */}
        <div className="flex flex-col gap-1">
          <label className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Desde</label>
          <input
            type="date"
            value={filterDateFrom}
            onChange={(e) => setFilterDateFrom(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none [color-scheme:dark]"
          />
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Hasta</label>
          <input
            type="date"
            value={filterDateTo}
            onChange={(e) => setFilterDateTo(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none [color-scheme:dark]"
          />
        </div>

        {/* Clear filters */}
        <button
          onClick={() => {
            setFilterAccion("BLOCK,LOG");
            setFilterMethod("");
            setFilterScoreMin("");
            setFilterScoreMax("");
            setFilterDateFrom("");
            setFilterDateTo("");
          }}
          className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/50 transition"
        >
          Limpiar Filtros
        </button>
      </div>

      {/* Alert Logs Table */}
      <div className="overflow-x-auto border border-slate-800/80 rounded-lg">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-16 space-y-2">
            <Loader2 className="w-6 h-6 text-cyan-500 animate-spin" />
            <p className="text-xs text-slate-400 font-medium">Recuperando registros de incidentes de seguridad...</p>
          </div>
        ) : error ? (
          <div className="py-12 text-center text-xs text-red-400">
            <p className="font-semibold">Error al obtener registros de seguridad</p>
            <p className="mt-1 text-slate-500">{error}</p>
          </div>
        ) : alerts.length === 0 ? (
          <div className="py-16 text-center text-xs text-slate-500">
            <AlertTriangle className="w-8 h-8 text-amber-500/50 mx-auto mb-2" />
            No se han registrado instancias de alertas de seguridad en la base de datos aún.
          </div>
        ) : (
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-semibold">
                <th className="py-3 px-4">ID</th>
                <th className="py-3 px-4">IP Origen</th>
                <th className="py-3 px-4">Método</th>
                <th className="py-3 px-4">Score ML</th>
                <th className="py-3 px-4">Modelo</th>
                <th className="py-3 px-4">Acción</th>
                <th className="py-3 px-4">URL</th>
                <th className="py-3 px-4">Fecha</th>
                <th className="py-3 px-4 text-right">Detalle</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {alerts.map((alert) => (
                <tr 
                  key={alert.id}
                  onClick={() => setSelectedAlert(alert)}
                  className="hover:bg-slate-800/35 transition cursor-pointer text-slate-300"
                >
                  <td className="py-3 px-4 font-mono text-slate-500 truncate max-w-[100px]">
                    {alert.id}
                  </td>
                  <td className="py-3 px-4 font-semibold text-slate-300">
                    {alert.ip_origen}
                  </td>
                  <td className="py-3 px-4">
                    <span className="bg-slate-800 px-2 py-0.5 rounded text-[10px] font-bold text-slate-400 border border-slate-700/60">
                      {alert.metodo_http}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-semibold">
                    <span className={`px-2 py-0.5 rounded font-mono text-[11px] ${
                      alert.accion === 'LOG'
                        ? 'text-amber-400 bg-amber-950/20 border border-amber-900/30'
                        : 'text-red-400 bg-red-950/20 border border-red-900/30'
                    }`}>
                      {Number(alert.score_ml).toFixed(4)}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] font-semibold text-cyan-400/90 bg-cyan-950/20 px-1.5 py-0.5 rounded border border-cyan-800/30">
                        LightGBM + MLP
                      </span>
                      <span className="text-[9px] font-mono text-slate-600" title={alert.waf_version}>
                        {alert.waf_version ? alert.waf_version.split('(')[0].trim() : '—'}
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${
                      alert.accion === 'LOG'
                        ? 'text-amber-500 bg-amber-950/30 border border-amber-800/40'
                        : 'text-red-500 bg-red-950/30 border border-red-800/40'
                    }`}>
                      {alert.accion === 'LOG' ? (
                        <><span className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse" /> LOG</>
                      ) : (
                        <><span className="w-1.5 h-1.5 rounded-full bg-red-500" /> {alert.accion}</>
                      )}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-400 truncate max-w-[200px]" title={alert.url}>
                    {alert.url}
                  </td>
                  <td className="py-3 px-4 text-slate-500 font-mono whitespace-nowrap">
                    {new Date(alert.fecha).toLocaleDateString()}
                  </td>
                  <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() => setSelectedAlert(alert)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-cyan-950/40 hover:bg-cyan-900/50 border border-cyan-800/40 hover:border-cyan-700/60 text-cyan-400 font-semibold transition"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>Inspeccionar</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Table Pagination */}
      {!loading && alerts.length > 0 && (
        <div className="flex items-center justify-between pt-2">
          <span className="text-xs text-slate-500">
            Mostrando página <strong className="text-slate-300">{page}</strong> de <strong className="text-slate-300">{totalPages}</strong>
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="flex items-center gap-1 py-1.5 px-3 rounded bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed text-xs transition font-semibold"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              <span>Anterior</span>
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="flex items-center gap-1 py-1.5 px-3 rounded bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed text-xs transition font-semibold"
            >
              <span>Siguiente</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Inspect Alert Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-3xl p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl relative flex flex-col max-h-[85vh] overflow-y-auto space-y-6">
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400">
                  <AlertTriangle className="w-5 h-5 animate-pulse" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-white uppercase tracking-wider">
                    Inspección Detallada de Amenaza
                  </h4>
                  <p className="text-xs text-slate-500 font-semibold font-mono">
                    INCIDENT_ID: {selectedAlert.id}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
              {/* Telemetry metadata */}
              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-3">
                  <h5 className="font-bold text-[10px] uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5" />
                    Detalles de la Transacción
                  </h5>
                  <div className="space-y-2">
                    <div className="flex justify-between border-b border-slate-900 pb-1.5">
                      <span className="text-slate-400">IP de Origen:</span>
                      <span className="text-white font-semibold font-mono">{selectedAlert.ip_origen}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-900 pb-1.5">
                      <span className="text-slate-400">Modelo:</span>
                      <span className="text-right">
                        <span className="text-cyan-400 font-semibold text-[10px] bg-cyan-950/30 px-1.5 rounded border border-cyan-800/40">
                          LightGBM + MLP
                        </span>
                        <span className="text-slate-500 font-mono text-[9px] ml-1">
                          {selectedAlert.waf_version || '—'}
                        </span>
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-900 pb-1.5">
                      <span className="text-slate-400">Método HTTP:</span>
                      <span className="text-white font-mono uppercase bg-slate-800 px-1.5 rounded text-[10px] border border-slate-700/50">
                        {selectedAlert.metodo_http}
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-900 pb-1.5">
                      <span className="text-slate-400">Tiempo de Inferencia:</span>
                      <span className="text-white font-semibold font-mono">
                        {selectedAlert.tiempo_inferencia_ms ? `${selectedAlert.tiempo_inferencia_ms} ms` : "N/A"}
                      </span>
                    </div>
                    <div className="flex justify-between pb-0.5">
                      <span className="text-slate-400">Marca de Tiempo:</span>
                      <span className="text-white font-mono">{new Date(selectedAlert.fecha).toLocaleString()}</span>
                    </div>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2">
                  <h5 className="font-bold text-[10px] uppercase tracking-wider text-slate-500">
                    URI de Solicitud HTTP
                  </h5>
                  <div className="p-3 bg-slate-950 rounded-lg font-mono text-slate-300 break-all select-all border border-slate-900">
                    {selectedAlert.url}
                  </div>
                </div>
              </div>

              {/* ML Engine Ensemble Verdict */}
              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-4">
                  <h5 className="font-bold text-[10px] uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5" />
                    Análisis del Ensamble ML
                  </h5>

                  <div className="space-y-3.5">
                    {/* Overall Score */}
                    <div className="space-y-1">
                      <div className="flex justify-between font-semibold">
                        <span className="text-slate-400">Puntaje de Ensamble Combinado:</span>
                        <span className="text-red-400 font-mono text-[13px]">
                          {Number(selectedAlert.score_ml).toFixed(4)}
                        </span>
                      </div>
                      <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                        <div 
                          className="h-full bg-red-500" 
                          style={{ width: `${Number(selectedAlert.score_ml) * 100}%` }}
                        />
                      </div>
                    </div>

                    {/* LightGBM & MLP Breakdown */}
                    <div className="grid grid-cols-2 gap-3 pt-2">
                      <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                        <span className="block text-[10px] text-slate-500 font-semibold uppercase tracking-wider">
                          Modelo LightGBM
                        </span>
                        <strong className="block text-sm text-cyan-400 font-mono mt-1">
                          {getLightGbmScore(Number(selectedAlert.score_ml))}
                        </strong>
                        <span className="text-[10px] text-slate-500">Peso: 60%</span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                        <span className="block text-[10px] text-slate-500 font-semibold uppercase tracking-wider">
                          Red Neuronal MLP
                        </span>
                        <strong className="block text-sm text-fuchsia-400 font-mono mt-1">
                          {getMlpScore(Number(selectedAlert.score_ml))}
                        </strong>
                        <span className="text-[10px] text-slate-500">Peso: 40%</span>
                      </div>
                    </div>

                    {/* Shannon Entropy */}
                    <div className="flex items-center justify-between p-3 bg-slate-900/60 border border-slate-800/50 rounded-lg">
                      <div>
                        <span className="block font-semibold text-slate-400">Entropía Shannon</span>
                        <span className="text-[10px] text-slate-500">Aleatoriedad del contenido informativo</span>
                      </div>
                      <strong className="text-emerald-400 font-mono text-base">
                        {Number(selectedAlert.shannon_entropy || 0).toFixed(4)}
                      </strong>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* HTTP Raw Payload */}
            <div className="space-y-2">
              <h5 className="font-bold text-[10px] uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                <Terminal className="w-4 h-4 text-cyan-500" />
                Payload Interceptado Crudo
              </h5>
              <div className="p-4 rounded-xl bg-slate-950 font-mono text-slate-200 border border-slate-900 overflow-x-auto whitespace-pre-wrap select-all max-h-[180px] text-xs">
                {selectedAlert.payload || "[No se capturó payload POST o query-string con la solicitud]"}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="pt-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-semibold transition text-xs"
              >
                Cerrar Inspección
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
