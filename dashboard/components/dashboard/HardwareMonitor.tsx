"use client";

import React, { useState, useEffect } from "react";
import { Cpu, HardDrive, Zap, Loader2, AlertCircle } from "lucide-react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts";

interface LatencyMetric {
  latency: number;
  timestamp: string;
}

interface HardwareMetric {
  container_name: string;
  cpu_usage_pct: number;
  ram_usage_mb: number;
  timestamp: string;
}

interface TelemetryData {
  latencies: LatencyMetric[];
  hardware: HardwareMetric[];
}

export default function HardwareMonitor() {
  const [data, setData] = useState<TelemetryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchTelemetry = async (isPoll = false) => {
    try {
      const res = await fetch("/dashboard/api/telemetry");
      if (!res.ok) {
        throw new Error("Failed to fetch hardware telemetry data");
      }
      const jsonData = await res.json();
      setData(jsonData);
      setError(null);
    } catch (err: any) {
      if (!isPoll) {
        setError(err.message || "An unexpected error occurred");
      }
    } finally {
      if (!isPoll) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    // Initial fetch
    fetchTelemetry(false);

    // Background polling every 5 seconds
    const interval = setInterval(() => {
      fetchTelemetry(true);
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[300px] border border-slate-800 bg-slate-900/25 rounded-2xl p-8 backdrop-blur-md">
        <Loader2 className="w-8 h-8 text-cyan-500 animate-spin mb-3" />
        <p className="text-sm text-slate-400 font-medium">Connecting to hardware metrics stream...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[300px] border border-red-900/30 bg-red-950/10 rounded-2xl p-8 backdrop-blur-md">
        <AlertCircle className="w-8 h-8 text-red-500 mb-3" />
        <p className="text-sm text-red-400 font-semibold mb-1">Hardware Monitor Failed</p>
        <p className="text-xs text-slate-500 max-w-md text-center">{error || "No data available"}</p>
      </div>
    );
  }

  // Reverse lists for proper chronological rendering (oldest to newest)
  const sortedLatencies = [...data.latencies].reverse();
  const sortedHardware = [...data.hardware].reverse();

  // Extract latest metrics for indicators
  const latestLatency = data.latencies[0]?.latency ?? 0;
  const uniqueContainers = Array.from(new Set(data.hardware.map((h) => h.container_name)));
  const latestMetricsByContainer = uniqueContainers.map((name) => {
    const records = data.hardware.filter((h) => h.container_name === name);
    return records[0] || { container_name: name, cpu_usage_pct: 0, ram_usage_mb: 0 };
  });

  return (
    <div className="space-y-6">
      {/* Top Title */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="font-bold text-sm tracking-wide text-white uppercase flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400 animate-pulse" />
            Infrastructure & Latency Monitoring
          </h3>
          <p className="text-xs text-slate-500">
            Real-time server resource metrics and WAF processing latencies (5s automatic polling)
          </p>
        </div>
      </div>

      {/* Quick Indicators */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/20 backdrop-blur-md flex items-center gap-4">
          <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Zap className="w-5 h-5" />
          </div>
          <div>
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">WAF Latency</span>
            <p className="text-xl font-bold text-white">{latestLatency.toFixed(2)} ms</p>
          </div>
        </div>

        {latestMetricsByContainer.map((container, index) => (
          <div
            key={index}
            className="p-4 rounded-xl border border-slate-800 bg-slate-900/20 backdrop-blur-md flex items-center gap-4"
          >
            <div className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <HardDrive className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                {container.container_name}
              </span>
              <p className="text-sm font-bold text-white">
                CPU: {container.cpu_usage_pct.toFixed(1)}% | RAM: {container.ram_usage_mb.toFixed(0)} MB
              </p>
            </div>
          </div>
        ))}
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Latency Line Chart */}
        <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/35 backdrop-blur-md shadow-lg space-y-4">
          <div>
            <h4 className="font-bold text-xs tracking-wide text-slate-400 uppercase">
              WAF Inference Latency Trend
            </h4>
            <p className="text-[11px] text-slate-500">Average engine decision latency in milliseconds</p>
          </div>
          <div className="h-64 w-full text-xs">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={sortedLatencies} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis
                  dataKey="timestamp"
                  stroke="#64748b"
                  tickFormatter={(t) => {
                    try {
                      return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
                    } catch (_) {
                      return t;
                    }
                  }}
                />
                <YAxis stroke="#64748b" label={{ value: "ms", angle: -90, position: "insideLeft", fill: "#64748b" }} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b", borderRadius: "8px" }}
                  labelStyle={{ color: "#94a3b8" }}
                />
                <Legend verticalAlign="top" height={36} />
                <Line
                  name="WAF Latency"
                  type="monotone"
                  dataKey="latency"
                  stroke="#22d3ee"
                  strokeWidth={2}
                  dot={{ r: 3 }}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Containers CPU & RAM Resource Line Chart */}
        <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/35 backdrop-blur-md shadow-lg space-y-4">
          <div>
            <h4 className="font-bold text-xs tracking-wide text-slate-400 uppercase">
              Container CPU & RAM Telemetry
            </h4>
            <p className="text-[11px] text-slate-500">Live virtualization layer resource utilization</p>
          </div>
          <div className="h-64 w-full text-xs">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={sortedHardware} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis
                  dataKey="timestamp"
                  stroke="#64748b"
                  tickFormatter={(t) => {
                    try {
                      return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
                    } catch (_) {
                      return t;
                    }
                  }}
                />
                <YAxis yAxisId="left" stroke="#64748b" label={{ value: "CPU (%)", angle: -90, position: "insideLeft", fill: "#64748b" }} />
                <YAxis yAxisId="right" orientation="right" stroke="#64748b" label={{ value: "RAM (MB)", angle: 90, position: "insideRight", fill: "#64748b" }} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b", borderRadius: "8px" }}
                  labelStyle={{ color: "#94a3b8" }}
                />
                <Legend verticalAlign="top" height={36} />
                <Line
                  yAxisId="left"
                  name="CPU %"
                  type="monotone"
                  dataKey="cpu_usage_pct"
                  stroke="#a855f7"
                  strokeWidth={2}
                  dot={{ r: 2 }}
                />
                <Line
                  yAxisId="right"
                  name="RAM MB"
                  type="monotone"
                  dataKey="ram_usage_mb"
                  stroke="#34d399"
                  strokeWidth={2}
                  dot={{ r: 2 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
