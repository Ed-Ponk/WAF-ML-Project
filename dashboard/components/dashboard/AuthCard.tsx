"use client";

import React, { useState } from "react";
import { Shield, Key, User, ArrowRight, Loader2 } from "lucide-react";

export default function AuthCard() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rbacInfo, setRbacInfo] = useState<string | null>(null);

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
      setRbacInfo(`Successfully logged in as ${role.toUpperCase()}`);
      
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
    <div className="w-full max-w-md p-8 rounded-2xl bg-slate-900/85 border border-slate-800 shadow-2xl backdrop-blur-md">
      <div className="flex flex-col items-center mb-8">
        <div className="p-3 mb-4 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
          <Shield className="w-8 h-8" />
        </div>
        <h2 className="text-2xl font-bold tracking-tight text-white text-center">
          WAF-ML CONTROL CENTER
        </h2>
        <p className="mt-2 text-sm text-slate-400 text-center">
          Administrative Access Portal — Secure Session Required
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
            Username or Email
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
              placeholder="Enter your administrative handle"
              className="w-full pl-10 pr-4 py-3 rounded-lg bg-slate-950 border border-slate-800 text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition duration-200 text-sm"
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
            Password
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
              className="w-full pl-10 pr-4 py-3 rounded-lg bg-slate-950 border border-slate-800 text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition duration-200 text-sm"
            />
          </div>
        </div>

        {error && (
          <div className="p-3.5 rounded-lg bg-red-950/40 border border-red-900/50 text-red-400 text-xs">
            <p className="font-semibold">Security Alert:</p>
            <p className="mt-0.5">{error}</p>
          </div>
        )}

        {rbacInfo && (
          <div className="p-3.5 rounded-lg bg-emerald-950/40 border border-emerald-900/50 text-emerald-400 text-xs font-medium">
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
              <span>Authenticating...</span>
            </>
          ) : (
            <>
              <span>Access WAF</span>
              <ArrowRight className="w-4 h-4" />
            </>
          )}
        </button>
      </form>
    </div>
  );
}
