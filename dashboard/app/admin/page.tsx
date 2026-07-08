import React from "react";
import GeneralTraffic from "../../components/dashboard/GeneralTraffic";

export default function AdminPage() {
  return (
    <div className="space-y-6 animate-fade-in pb-10">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white uppercase">
          Panel General de Telemetría
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Métricas integrales de inspección, clasificaciones del modelo y alertas de eventos de seguridad cronológicas
        </p>
      </div>
      <GeneralTraffic />
    </div>
  );
}
