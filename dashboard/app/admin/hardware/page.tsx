import React from "react";
import HardwareMonitor from "../../../components/dashboard/HardwareMonitor";

export default function HardwarePage() {
  return (
    <div className="space-y-6 animate-fade-in pb-10">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white uppercase">
          Métricas de Hardware
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Monitoreo en tiempo real del uso de recursos de contenedores, carga de CPU y latencia de inferencia
        </p>
      </div>
      <HardwareMonitor />
    </div>
  );
}
