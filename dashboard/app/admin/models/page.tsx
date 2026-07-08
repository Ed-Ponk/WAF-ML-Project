import React from "react";
import ModelManagement from "../../../components/dashboard/ModelManagement";

export default function ModelsPage() {
  return (
    <div className="space-y-6 animate-fade-in pb-10">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white uppercase">
          Modelos
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Registro de modelos ML activos e interfaz segura de carga .pkl
        </p>
      </div>
      <ModelManagement />
    </div>
  );
}
