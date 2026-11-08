import React from "react";
import AppManagement from "../../../components/dashboard/AppManagement";

export default function AppsPage() {
  return (
    <div className="space-y-6 animate-fade-in pb-10">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white uppercase">
          Aplicaciones
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Registro de aplicaciones protegidas por el WAF-ML: dominios, backend y estado
        </p>
      </div>
      <AppManagement />
    </div>
  );
}
