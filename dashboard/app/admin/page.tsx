import React from "react";
import GeneralTraffic from "../../components/dashboard/GeneralTraffic";
import AlertTable from "../../components/dashboard/AlertTable";

export default function AdminPage() {
  return (
    <div className="space-y-8 animate-fade-in">
      {/* Page Title */}
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white uppercase">
          General Telemetry Dashboard
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Comprehensive inspection metrics, model classifications, and chronological secure event alerts
        </p>
      </div>

      {/* KPI Cards and Charts */}
      <GeneralTraffic />

      {/* Alert logs list */}
      <div className="pt-2">
        <AlertTable />
      </div>
    </div>
  );
}
