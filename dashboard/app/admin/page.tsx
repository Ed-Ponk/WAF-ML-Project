import React from "react";
import GeneralTraffic from "../../components/dashboard/GeneralTraffic";
import AlertTable from "../../components/dashboard/AlertTable";
import HardwareMonitor from "../../components/dashboard/HardwareMonitor";
import ModelManagement from "../../components/dashboard/ModelManagement";
import ConfusionMatrix from "../../components/dashboard/ConfusionMatrix";

export default function AdminPage() {
  return (
    <div className="space-y-10 animate-fade-in pb-10">
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

      {/* Hardware Monitor */}
      <div className="pt-2">
        <HardwareMonitor />
      </div>

      {/* Confusion Matrix / Performance Benchmarking */}
      <div className="pt-2">
        <ConfusionMatrix />
      </div>

      {/* Model Management / Drag & Drop Upload */}
      <div className="pt-2">
        <ModelManagement />
      </div>

      {/* Alert logs list */}
      <div className="pt-2">
        <AlertTable />
      </div>
    </div>
  );
}
