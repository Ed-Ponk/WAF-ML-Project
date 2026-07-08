import React from "react";
import ConfusionMatrix from "../../../components/dashboard/ConfusionMatrix";

export default function BaselinesPage() {
  return (
    <div className="space-y-6 animate-fade-in pb-10">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white uppercase">
          Matriz de Línea Base
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Matriz de confusión comparativa y líneas base de rendimiento contra ModSecurity, Coraza y NAXSI — datos de referencia del benchmark (solo lectura)
        </p>
      </div>
      <ConfusionMatrix />
    </div>
  );
}
