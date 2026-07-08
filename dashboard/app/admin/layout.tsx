"use client";

import React, { useState } from "react";
import { usePathname } from "next/navigation";
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Settings, 
  Cpu, 
  FolderLock, 
  LogOut, 
  User,
  Loader2,
  Menu,
  X,
  FileText,
} from "lucide-react";

export default function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [loggingOut, setLoggingOut] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const pathname = usePathname();

  // Normalize path: strip basePath prefix if present, then match against menu hrefs
  const currentPath = pathname.replace(/^\/dashboard/, "") || "/";

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

  const handleNavClick = () => {
    setSidebarOpen(false);
  };

  const menuItems = [
    { label: "Panel General", icon: Activity, href: "/dashboard/admin" },
    { label: "Alertas de Seguridad", icon: AlertTriangle, href: "/dashboard/admin/alerts" },
    { label: "Modelos", icon: FolderLock, href: "/dashboard/admin/models" },
    { label: "Línea Base", icon: Settings, href: "/dashboard/admin/baselines" },
    { label: "Hardware", icon: Cpu, href: "/dashboard/admin/hardware" },
    { label: "Reportes e Informes", icon: FileText, href: "/dashboard/admin/reports" },
  ];

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100">
      {/* Mobile overlay backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-20 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar navigation */}
      <aside
        className={`
          fixed inset-y-0 left-0 z-30 w-64 border-r border-slate-800 
          bg-slate-900/95 backdrop-blur-md flex flex-col justify-between p-4
          transition-transform duration-200 ease-in-out
          lg:static lg:translate-x-0
          ${sidebarOpen ? "translate-x-0" : "-translate-x-full"}
        `}
      >
        <div>
          {/* Brand header with mobile close */}
          <div className="flex items-center justify-between px-2 py-4 mb-6 border-b border-slate-800">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <h1 className="font-bold text-sm leading-none text-white tracking-wider">
                  WAF-ML ENGINE
                </h1>
                <span className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold">
                  Panel de Control
                </span>
              </div>
            </div>
            <button
              className="lg:hidden text-slate-400 hover:text-white transition-colors"
              onClick={() => setSidebarOpen(false)}
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation menus */}
          <nav className="space-y-1">
            {menuItems.map((item, idx) => {
              const isActive = currentPath === item.href.replace("/dashboard", "") || 
                               (currentPath === "/" && item.href === "/dashboard/admin");
              return (
                <a
                  key={idx}
                  href={item.href}
                  onClick={handleNavClick}
                  className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition duration-150 ${
                    isActive
                      ? "text-white bg-cyan-500/10 border border-cyan-500/20"
                      : "text-slate-400 hover:text-white hover:bg-slate-800/55"
                  }`}
                >
                  <item.icon className={`w-4 h-4 ${isActive ? "text-cyan-400" : "text-cyan-500/80"}`} />
                  <span>{item.label}</span>
                </a>
              );
            })}
          </nav>
        </div>

        {/* User status and logout */}
        <div className="border-t border-slate-800 pt-4 px-2 space-y-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-full bg-slate-800 text-slate-400">
              <User className="w-4 h-4" />
            </div>
            <div className="overflow-hidden">
              <p className="text-xs font-semibold text-slate-300 truncate">Administrador</p>
              <span className="text-[10px] uppercase font-bold text-cyan-500 tracking-wide bg-cyan-950/40 px-1.5 py-0.5 rounded border border-cyan-900/30">
                SESIÓN ACTIVA
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
            <span>Cerrar Sesión</span>
          </button>
        </div>
      </aside>

      {/* Main dashboard content area */}
      <div className="flex-1 flex flex-col min-h-screen min-w-0 overflow-y-auto">
        {/* Top telemetry bar */}
        <header className="h-16 border-b border-slate-800 flex items-center justify-between bg-slate-900/10 px-4 md:px-8 gap-4">
          <div className="flex items-center gap-3 min-w-0">
            {/* Mobile hamburger */}
            <button
              className="lg:hidden text-slate-400 hover:text-white transition-colors shrink-0"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu className="w-5 h-5" />
            </button>
            <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse shrink-0" />
            <span className="text-xs text-slate-400 font-medium truncate">
              AI Model: Whitelisted (LightGBM + MLP)
            </span>
          </div>
          <div className="text-xs text-slate-500 shrink-0 hidden sm:block">
            WAF-ML Core v1.0.0
          </div>
        </header>

        {/* Dynamic children screens */}
        <main className="flex-1 p-4 md:p-8">
          {children}
        </main>
      </div>
    </div>
  );
}
