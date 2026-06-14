"use client";

import React, { useState, useEffect } from "react";
import { 
  Activity, 
  ShieldCheck, 
  ShieldAlert, 
  Percent, 
  Loader2, 
  AlertCircle 
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  PieChart,
  Pie,
  Cell
} from "recharts";

interface Totals {
  requests: number;
  blocked: number;
  allowed: number;
  blockRate: number;
  attacks: {
    sqli: number;
    xss: number;
    rce: number;
  };
}

interface DailyRecord {
  date: string;
  requests: number;
  blocked: number;
  allowed: number;
  sqli: number;
  xss: number;
  rce: number;
}

interface StatsData {
  totals: Totals;
  daily: DailyRecord[];
}

export default function GeneralTraffic() {
  const [data, setData] = useState<StatsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchStats() {
      try {
        const res = await fetch("/dashboard/api/stats");
        if (!res.ok) {
          throw new Error("Failed to fetch traffic telemetry stats");
        }
        const jsonData = await res.ok ? await res.json() : null;
        setData(jsonData);
      } catch (err: any) {
        setError(err.message || "An unexpected error occurred");
      } finally {
        setLoading(false);
      }
    }
    fetchStats();
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] border border-slate-800 bg-slate-900/25 rounded-2xl p-8 backdrop-blur-md">
        <Loader2 className="w-8 h-8 text-cyan-500 animate-spin mb-3" />
        <p className="text-sm text-slate-400 font-medium">Aggregating telemetry reports...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] border border-red-900/30 bg-red-950/10 rounded-2xl p-8 backdrop-blur-md">
        <AlertCircle className="w-8 h-8 text-red-500 mb-3" />
        <p className="text-sm text-red-400 font-semibold mb-1">Telemetry Gathering Failed</p>
        <p className="text-xs text-slate-500 max-w-md text-center">{error || "No data available"}</p>
      </div>
    );
  }

  const { totals, daily } = data;

  // Formatting Pie Chart Data
  const pieData = [
    { name: "SQLi (SQL Injection)", value: totals.attacks.sqli },
    { name: "XSS (Cross-Site Scripting)", value: totals.attacks.xss },
    { name: "RCE (Remote Code Execution)", value: totals.attacks.rce }
  ].filter(item => item.value > 0);

  // Fallback if no attack types detected
  if (pieData.length === 0) {
    pieData.push({ name: "No Attacks Logged", value: 1 });
  }

  const PIE_COLORS = ["#22d3ee", "#a855f7", "#ef4444"];

  const kpis = [
    {
      label: "Total Requests",
      value: totals.requests.toLocaleString(),
      icon: Activity,
      colorClass: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",
    },
    {
      label: "Allowed Requests",
      value: totals.allowed.toLocaleString(),
      icon: ShieldCheck,
      colorClass: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    },
    {
      label: "Blocked Requests",
      value: totals.blocked.toLocaleString(),
      icon: ShieldAlert,
      colorClass: "text-red-400 bg-red-500/10 border-red-500/20",
    },
    {
      label: "Block Rate",
      value: `${totals.blockRate}%`,
      icon: Percent,
      colorClass: "text-fuchsia-400 bg-fuchsia-500/10 border-fuchsia-500/20",
    },
  ];

  return (
    <div className="space-y-6">
      {/* KPI Section */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {kpis.map((kpi, idx) => {
          const IconComp = kpi.icon;
          return (
            <div 
              key={idx} 
              className="p-5 rounded-xl border border-slate-800 bg-slate-900/35 backdrop-blur-md flex items-center justify-between shadow-lg"
            >
              <div className="space-y-1">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                  {kpi.label}
                </span>
                <p className="text-2xl font-bold text-white tracking-tight">
                  {kpi.value}
                </p>
              </div>
              <div className={`p-3 rounded-lg border ${kpi.colorClass}`}>
                <IconComp className="w-5 h-5" />
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* AreaChart: Traffic trends */}
        <div className="lg:col-span-2 p-6 rounded-xl border border-slate-800 bg-slate-900/35 backdrop-blur-md shadow-lg space-y-4">
          <div>
            <h3 className="font-bold text-sm tracking-wide text-white uppercase">
              Traffic Volumes Over Time
            </h3>
            <p className="text-xs text-slate-500">
              Chronological summary of allowed vs. blocked requests
            </p>
          </div>
          <div className="h-72 w-full text-xs">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={daily} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="date" stroke="#64748b" />
                <YAxis stroke="#64748b" />
                <Tooltip 
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b", borderRadius: "8px" }}
                  labelStyle={{ color: "#94a3b8", fontWeight: "bold" }}
                />
                <Legend verticalAlign="top" height={36} iconType="circle" />
                <Area 
                  name="Allowed" 
                  type="monotone" 
                  dataKey="allowed" 
                  stroke="#10b981" 
                  fillOpacity={1} 
                  fill="url(#colorAllowed)" 
                />
                <Area 
                  name="Blocked" 
                  type="monotone" 
                  dataKey="blocked" 
                  stroke="#ef4444" 
                  fillOpacity={1} 
                  fill="url(#colorBlocked)" 
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* PieChart: Attack distribution */}
        <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/35 backdrop-blur-md shadow-lg flex flex-col justify-between space-y-4">
          <div>
            <h3 className="font-bold text-sm tracking-wide text-white uppercase">
              Attack Distribution
            </h3>
            <p className="text-xs text-slate-500">
              Aggregated threat payload classification
            </p>
          </div>
          <div className="h-56 w-full flex items-center justify-center relative text-xs">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b", borderRadius: "8px" }}
                />
              </PieChart>
            </ResponsiveContainer>
            {totals.blocked === 0 && (
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <span className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold">
                  No Threats Logged
                </span>
              </div>
            )}
          </div>
          <div className="space-y-1 text-xs">
            {pieData.map((item, index) => (
              <div key={idx => index} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span 
                    className="w-2.5 h-2.5 rounded-full" 
                    style={{ backgroundColor: PIE_COLORS[index % PIE_COLORS.length] }} 
                  />
                  <span className="text-slate-400 font-medium">{item.name}</span>
                </div>
                <span className="text-white font-bold">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
