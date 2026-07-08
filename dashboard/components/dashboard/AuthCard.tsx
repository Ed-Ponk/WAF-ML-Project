"use client";

import React, { useState, useEffect, useRef } from "react";
import { Shield, Key, User, ArrowRight, Loader2, CheckCircle2, AlertTriangle } from "lucide-react";

export default function AuthCard() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rbacInfo, setRbacInfo] = useState<string | null>(null);
  const [scanStep, setScanStep] = useState(0);
  const scanInterval = useRef<ReturnType<typeof setInterval> | null>(null);

  const SCAN_STEPS = [
    "Verificando credenciales...",
    "Escaneando perfil de seguridad...",
    "Validando RBAC...",
    "Estableciendo sesión cifrada...",
    "Inicializando panel de control...",
  ];

  useEffect(() => {
    if (loading) {
      setScanStep(0);
      scanInterval.current = setInterval(() => {
        setScanStep((prev) => {
          if (prev < SCAN_STEPS.length - 1) return prev + 1;
          return prev;
        });
      }, 600);
    } else {
      if (scanInterval.current) clearInterval(scanInterval.current);
      setScanStep(0);
    }
    return () => {
      if (scanInterval.current) clearInterval(scanInterval.current);
    };
  }, [loading]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setRbacInfo(null);

    try {
      const response = await fetch("/dashboard/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Authentication failed");
      }

      // Display RBAC feedback
      const role = data.user.role;
      setRbacInfo(`Sesión iniciada como ${role.toUpperCase()}`);
      
      // Redirect after showing success
      setTimeout(() => {
        window.location.href = "/dashboard/admin";
      }, 1000);
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md rounded-2xl bg-slate-900/85 border border-slate-800 shadow-2xl backdrop-blur-md overflow-hidden relative">
      {/* Loading overlay with scanning animation */}
      {loading && (
        <div className="absolute inset-0 z-20 flex flex-col items-center justify-center bg-slate-950/90 backdrop-blur-sm animate-fade-in">
          {/* Animated shield with scan line */}
          <div className="relative mb-6">
            <div className="p-4 rounded-full bg-cyan-500/10 border-2 border-cyan-500/30 animate-pulse">
              <Shield className="w-10 h-10 text-cyan-400" />
            </div>
            {/* Rotating ring */}
            <div className="absolute -inset-2 rounded-full border-2 border-transparent border-t-cyan-500/50 animate-spin" />
            <div className="absolute -inset-3 rounded-full border border-transparent border-b-cyan-500/20 animate-spin" style={{ animationDuration: "3s" }} />
          </div>

          {/* Scan progress bar */}
          <div className="w-48 h-1 bg-slate-800 rounded-full overflow-hidden mb-4">
            <div
              className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-500 ease-out"
              style={{ width: `${((scanStep + 1) / SCAN_STEPS.length) * 100}%` }}
            />
          </div>

          {/* Scan step text */}
          <p className="text-xs text-cyan-300 font-mono tracking-wider animate-pulse">
            {SCAN_STEPS[scanStep]}
          </p>
          <p className="text-[10px] text-slate-600 mt-2 font-mono">
            {new Array(8).fill(0).map((_, i) => {
              const hex = Math.floor(Math.random() * 256).toString(16).padStart(2, "0");
              return (
                <span key={i} className="mx-0.5 opacity-60">
                  {hex}
                </span>
              );
            })}
          </p>
        </div>
      )}

      <div className={`p-8 transition-opacity duration-200 ${loading ? "opacity-0" : "opacity-100"}`}>
        <div className="flex flex-col items-center mb-8">
          <div className="p-3 mb-4 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Shield className="w-8 h-8" />
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-white text-center">
            WAF-ML CONTROL CENTRAL
          </h2>
          <p className="mt-2 text-sm text-slate-400 text-center">
            Portal de Acceso Administrativo — Sesión Segura Requerida
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Usuario o Correo
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
                <User className="w-4 h-4" />
              </span>
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Ingrese su identificador administrativo"
                disabled={loading}
                className="w-full pl-10 pr-4 py-3 rounded-lg bg-slate-950 border border-slate-800 text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition duration-200 text-sm disabled:opacity-30"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
Contraseña
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
                <Key className="w-4 h-4" />
              </span>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                disabled={loading}
                className="w-full pl-10 pr-4 py-3 rounded-lg bg-slate-950 border border-slate-800 text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition duration-200 text-sm disabled:opacity-30"
              />
            </div>
          </div>

          {error && (
            <div className="p-3.5 rounded-lg bg-red-950/40 border border-red-900/50 text-red-400 text-xs flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
              <div>
                <p className="font-semibold">Alerta de Seguridad:</p>
                <p className="mt-0.5">{error}</p>
              </div>
            </div>
          )}

          {rbacInfo && (
            <div className="p-3.5 rounded-lg bg-emerald-950/40 border border-emerald-900/50 text-emerald-400 text-xs font-medium flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              {rbacInfo}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-sm transition duration-200 shadow-lg shadow-cyan-950/50 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Autenticando...</span>
              </>
            ) : (
              <>
                <span>Acceder a WAF</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
