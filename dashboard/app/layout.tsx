import './globals.css';
import { ReactNode } from 'react';

export const metadata = {
  title: 'WAF-ML Admin Dashboard',
  description: 'Administrative control and security telemetry panel for WAF-ML',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="es" className="dark">
      <body className="bg-[#02040a] text-slate-100 antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
        {children}
      </body>
    </html>
  );
}
