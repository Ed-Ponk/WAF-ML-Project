import React from "react";
import AlertTable from "../../../components/dashboard/AlertTable";

export default function AlertsPage() {
  return (
    <div className="space-y-6 animate-fade-in pb-10">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white uppercase">
          Alertas de Seguridad
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Registros cronológicos de eventos de seguridad con inspección de payload, análisis de entropía y veredictos del modelo ML
        </p>
      </div>
      <AlertTable />
    </div>
  );
}
