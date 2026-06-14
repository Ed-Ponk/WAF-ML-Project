import React from "react";
import AuthCard from "../../components/dashboard/AuthCard";

export default function LoginPage() {
  return (
    <main className="relative min-h-screen flex items-center justify-center bg-slate-950 overflow-hidden">
      {/* Background cyan neon grid elements */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#020617_1px,transparent_1px),linear-gradient(to_bottom,#020617_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-35" />
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[350px] bg-cyan-500/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-0 right-10 w-[300px] h-[300px] bg-blue-500/5 rounded-full blur-[100px] pointer-events-none" />

      <div className="relative z-10 w-full px-4 flex flex-col items-center">
        <AuthCard />
        
        {/* Security disclaimer */}
        <p className="mt-8 text-xs text-slate-600 text-center max-w-sm tracking-wide leading-relaxed">
          WARNING: Unprivileged attempts to access this dashboard are monitored under standard WAF incident response protocols.
        </p>
      </div>
    </main>
  );
}
