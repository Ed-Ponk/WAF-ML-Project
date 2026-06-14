"use client";

import React, { useState } from "react";
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Settings, 
  Cpu, 
  FolderLock, 
  LogOut, 
  User,
  Loader2
} from "lucide-react";

export default function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [loggingOut, setLoggingOut] = useState(false);

  const handleLogout = async () => {
    setLoggingOut(true);
    try {
      const response = await fetch("/dashboard/api/auth", {
        method: "DELETE",
      });
      if (response.ok) {
        window.location.href = "/dashboard/login";
      }
    } catch (error) {
      console.error("Logout failed:", error);
    } finally {
      setLoggingOut(false);
    }
  };

  const menuItems = [
    { label: "General Telemetry", icon: Activity, href: "/dashboard/admin" },
    { label: "Security Alerts", icon: AlertTriangle, href: "/dashboard/admin/alerts" },
    { label: "Model Whitelist", icon: FolderLock, href: "/dashboard/admin/models" },
    { label: "Baseline Matrix", icon: Settings, href: "/dashboard/admin/baselines" },
    { label: "Hardware Metrics", icon: Cpu, href: "/dashboard/admin/hardware" },
  ];

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100">
      {/* Sidebar navigation */}
      <aside className="w-64 border-r border-slate-800 bg-slate-900/40 backdrop-blur-md flex flex-col justify-between p-4">
        <div>
          {/* Brand header */}
          <div className="flex items-center gap-3 px-2 py-4 mb-6 border-b border-slate-800">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="font-bold text-sm leading-none text-white tracking-wider">
                WAF-ML ENGINE
              </h1>
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold">
                Control Panel
              </span>
            </div>
          </div>

          {/* Navigation menus */}
          <nav className="space-y-1">
            {menuItems.map((item, idx) => (
              <a
                key={idx}
                href={item.href}
                className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-400 hover:text-white hover:bg-slate-800/55 transition duration-150"
              >
                <item.icon className="w-4 h-4 text-cyan-500/80" />
                <span>{item.label}</span>
              </a>
            ))}
          </nav>
        </div>

        {/* User status and logout */}
        <div className="border-t border-slate-800 pt-4 px-2 space-y-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-full bg-slate-800 text-slate-400">
              <User className="w-4 h-4" />
            </div>
            <div className="overflow-hidden">
              <p className="text-xs font-semibold text-slate-300 truncate">Administrator</p>
              <span className="text-[10px] uppercase font-bold text-cyan-500 tracking-wide bg-cyan-950/40 px-1.5 py-0.5 rounded border border-cyan-900/30">
                ACTIVE SESSION
              </span>
            </div>
          </div>

          <button
            onClick={handleLogout}
            disabled={loggingOut}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold text-red-400 hover:text-red-300 hover:bg-red-950/20 border border-transparent hover:border-red-900/40 transition duration-150"
          >
            {loggingOut ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <LogOut className="w-3.5 h-3.5" />
            )}
            <span>Terminate Session</span>
          </button>
        </div>
      </aside>

      {/* Main dashboard content area */}
      <div className="flex-1 flex flex-col min-h-screen overflow-y-auto">
        {/* Top telemetry bar */}
        <header className="h-16 border-b border-slate-800 px-8 flex items-center justify-between bg-slate-900/10">
          <div className="flex items-center gap-3 text-xs text-slate-400 font-medium">
            <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>AI Model Validation Status: Whitelisted (LightGBM + MLP)</span>
          </div>
          <div className="text-xs text-slate-500">
            WAF-ML Core Node: v1.0.0
          </div>
        </header>

        {/* Dynamic children screens */}
        <main className="flex-1 p-8">
          {children}
        </main>
      </div>
    </div>
  );
}
