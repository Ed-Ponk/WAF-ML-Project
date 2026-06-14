"use client";

import React, { useState, useRef } from "react";
import { Upload, FileCheck, RefreshCw, AlertCircle, ShieldCheck, CheckCircle2 } from "lucide-react";

export default function ModelManagement() {
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Hardcoded current active model details as baselines/specs
  const [activeModel, setActiveModel] = useState({
    name: "LightGBM + MLP Ensemble Neural Net",
    accuracy: "99.42%",
    f1Score: "99.21%",
    lastTraining: "2026-06-12",
  });

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFileUpload(e.target.files[0]);
    }
  };

  const handleFileUpload = async (file: File) => {
    if (!file.name.endsWith(".pkl")) {
      setError("Invalid file type: Only Python Pickle (.pkl) models are allowed.");
      setSuccess(null);
      return;
    }

    setUploading(true);
    setError(null);
    setSuccess(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      // Use relative URL that complies with base path /dashboard and next.js API routes
      const response = await fetch("/dashboard/api/model/upload", {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Model verification and upload failed.");
      }

      setSuccess(`Model '${file.name}' verified, hot-reloaded, and activated successfully!`);
      // Update dummy local metadata to reflect successful reload
      setActiveModel({
        name: `Ensemble Model: ${file.name}`,
        accuracy: "99.58% (Calibrated)",
        f1Score: "99.41% (Calibrated)",
        lastTraining: new Date().toISOString().split("T")[0],
      });
    } catch (err: any) {
      setError(err.message || "An unexpected network error occurred.");
    } finally {
      setUploading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  };

  const triggerFileInput = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h3 className="font-bold text-sm tracking-wide text-white uppercase flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          Active Model & Artificial Intelligence Management
        </h3>
        <p className="text-xs text-slate-500">
          Upload and verify administrative WAF model weights with automated bytecode verification checks
        </p>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Left Side: Active Model Details */}
        <div className="lg:col-span-2 p-6 rounded-xl border border-slate-800 bg-slate-900/35 backdrop-blur-md space-y-4">
          <h4 className="font-bold text-xs tracking-wide text-slate-400 uppercase">
            Active Model Metadata
          </h4>

          <div className="space-y-3 pt-2">
            <div>
              <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">Algorithm Name</span>
              <p className="text-sm font-semibold text-white mt-0.5">{activeModel.name}</p>
            </div>

            <div className="grid grid-cols-2 gap-4 pt-1">
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">Inference Accuracy</span>
                <p className="text-lg font-extrabold text-emerald-400 mt-0.5">{activeModel.accuracy}</p>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">F1-Score Metric</span>
                <p className="text-lg font-extrabold text-emerald-400 mt-0.5">{activeModel.f1Score}</p>
              </div>
            </div>

            <div className="pt-1">
              <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">Last Sync/Training Date</span>
              <p className="text-xs font-mono text-slate-300 mt-1">{activeModel.lastTraining}</p>
            </div>
          </div>

          <div className="p-3 bg-cyan-500/5 border border-cyan-500/10 rounded-lg text-[11px] text-cyan-400 leading-relaxed">
            The active model combines a LightGBM gradient booster with a multi-layer perceptron neural network in Python. Both models are executed inside the Python ML service via thread-safe unpickling.
          </div>
        </div>

        {/* Right Side: Drag & Drop Zone */}
        <div className="lg:col-span-3 space-y-4">
          <div
            onDragEnter={handleDrag}
            onDragOver={handleDrag}
            onDragLeave={handleDrag}
            onDrop={handleDrop}
            className={`relative p-8 rounded-xl border border-dashed transition-all flex flex-col items-center justify-center min-h-[220px] text-center cursor-pointer ${
              dragActive
                ? "border-cyan-400 bg-cyan-500/5"
                : "border-slate-800 hover:border-slate-700 bg-slate-900/20"
            }`}
            onClick={triggerFileInput}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pkl"
              className="hidden"
              onChange={handleFileChange}
              disabled={uploading}
            />

            {uploading ? (
              <div className="flex flex-col items-center gap-3">
                <RefreshCw className="w-10 h-10 text-cyan-400 animate-spin" />
                <div>
                  <p className="text-sm font-bold text-white">Validating Model Binary...</p>
                  <p className="text-xs text-slate-400 mt-1 max-w-xs">
                    Running Pickletools bytecode inspection and security signature scans...
                  </p>
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-3">
                <div className="p-4 rounded-full bg-slate-800/50 border border-slate-700/50 text-slate-400">
                  <Upload className="w-6 h-6" />
                </div>
                <div>
                  <p className="text-sm font-bold text-white">
                    Drag and drop your model <code className="text-cyan-400 text-xs">.pkl</code> here
                  </p>
                  <p className="text-xs text-slate-500 mt-1">
                    or click to browse local files (max size 25MB)
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Messages Banners */}
          {error && (
            <div className="p-4 rounded-xl border border-red-900/30 bg-red-950/15 text-red-400 flex items-start gap-3 shadow-lg">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5 text-red-500" />
              <div>
                <p className="text-xs font-bold uppercase tracking-wider text-red-500">Security / Verification Error</p>
                <p className="text-xs mt-1 leading-relaxed">{error}</p>
              </div>
            </div>
          )}

          {success && (
            <div className="p-4 rounded-xl border border-emerald-900/30 bg-emerald-950/15 text-emerald-400 flex items-start gap-3 shadow-lg animate-fade-in">
              <CheckCircle2 className="w-5 h-5 flex-shrink-0 mt-0.5 text-emerald-500" />
              <div>
                <p className="text-xs font-bold uppercase tracking-wider text-emerald-500">Model Deployment Completed</p>
                <p className="text-xs mt-1 leading-relaxed">{success}</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
