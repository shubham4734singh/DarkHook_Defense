import { motion } from 'motion/react';
import {
  Link as LinkIcon,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ArrowLeft,
  LogOut,
  Sparkles,
  Gauge,
  ShieldAlert,
  ScanLine,
  Trash2,
  ClipboardPaste,
  Globe,
  Lock,
  Unlock,
  FileCode,
  CornerDownRight,
  ExternalLink,
  ShieldCheck,
  Cpu,
  Terminal,
  Calendar,
  Key,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  Activity,
  Database,
  Hash,
  Fingerprint,
  Clock,
  Percent,
  Shield,
} from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { useAuth } from '../contexts/AuthContext';
import { api, type UrlScanResult } from '../services/api';
import logo from '@/assets/eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png';

const LAST_URL_SCAN_RESULT_KEY = 'darkhook_latest_url_scan_result';

const sampleUrls = [
  'https://example.com',
  'https://accounts.google.com',
  'http://paypa1.com/login',
  'https://secure-login.tk/verify',
];

export function URLScan() {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<UrlScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const { logout } = useAuth();

  const trimmedUrl = url.trim();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const handleScan = async () => {
    if (!trimmedUrl) return;

    setScanning(true);
    setResult(null);
    setError(null);

    try {
      const response = await api.scanUrl(trimmedUrl);
      setResult(response);
      sessionStorage.setItem(LAST_URL_SCAN_RESULT_KEY, JSON.stringify(response));
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Scan failed. Please try again.');
    } finally {
      setScanning(false);
    }
  };

  const fillSample = (value: string) => {
    setUrl(value);
    setError(null);
  };

  const clearForm = () => {
    setUrl('');
    setResult(null);
    setError(null);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'safe': return '#00D68F';
      case 'suspicious': return '#FFAA00';
      case 'phishing': return '#FF3B3B';
      default: return '#1E3A5F';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'safe': return <CheckCircle className="w-5 h-5" />;
      case 'suspicious': return <AlertTriangle className="w-5 h-5" />;
      default: return <XCircle className="w-5 h-5" />;
    }
  };

  const analysisDetails = result?.analysis_details;
  const riskFactors = analysisDetails?.risk_factors ?? [];
  const recommendations = analysisDetails?.recommendations ?? [];
  const topRisks = analysisDetails?.top_risks ?? [];
  const parsedUrl = analysisDetails?.parsed_url;
  const dynamicAnalysis = analysisDetails?.dynamic_analysis;
  const screenshotData = dynamicAnalysis?.screenshot ?? result?.screenshot;
  const confidenceLabel = result?.status === 'safe' ? 'Verdict Confidence' : 'Detection Confidence';
  const confidencePercent = Math.round((result?.confidence ?? 0) * 100);
  const scoreTone = result?.status === 'safe'
    ? 'from-emerald-500/20 via-cyan-500/10 to-transparent'
    : result?.status === 'suspicious'
      ? 'from-amber-500/20 via-orange-500/10 to-transparent'
      : 'from-rose-500/25 via-red-500/10 to-transparent';

  return (
    <div className="min-h-screen bg-[#050A14] text-white relative overflow-hidden">
      {/* Background Glows */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute -top-24 -left-20 h-72 w-72 rounded-full bg-[#00C2FF]/10 blur-3xl" />
        <div className="absolute top-40 -right-24 h-96 w-96 rounded-full bg-[#7C3AED]/10 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-80 w-80 rounded-full bg-[#10B981]/10 blur-3xl" />
      </div>

      {/* Top Navbar */}
      <nav className="fixed top-0 left-0 right-0 z-50 h-[72px] bg-[#07111F]/80 backdrop-blur-2xl border-b border-[#18304E]">
        <div className="max-w-[1440px] mx-auto px-4 h-full flex items-center justify-between">
          <Link to="/dashboard" className="flex items-center gap-3 cursor-pointer">
            <img src={logo} alt="Darkhook Defense" className="h-12" />
            <div className="hidden md:block">
              <p className="text-[11px] uppercase tracking-[0.28em] text-[#7FA0C4]">DarkHook Defense</p>
              <p className="text-sm text-white/90 font-semibold">URL Analysis Console</p>
            </div>
          </Link>

          <div className="flex items-center gap-3 sm:gap-5">
            <Link
              to="/dashboard"
              className="inline-flex items-center gap-2 px-3 sm:px-4 py-2 rounded-full border border-[#1C3657] bg-white/5 text-[#A7C1DB] hover:text-white hover:border-[#00C2FF]/50 hover:bg-[#00C2FF]/10 transition-all"
            >
              <ArrowLeft className="w-4 h-4" />
              <span className="hidden sm:inline">Dashboard</span>
            </Link>
            <button
              onClick={handleLogout}
              className="inline-flex items-center gap-2 px-3 sm:px-4 py-2 rounded-full border border-[#1C3657] bg-white/5 text-[#A7C1DB] hover:text-white hover:border-[#00C2FF]/50 hover:bg-[#00C2FF]/10 transition-all"
            >
              <LogOut className="w-4 h-4" />
              <span className="hidden sm:inline">Logout</span>
            </button>
          </div>
        </div>
      </nav>

      <main className="relative pt-[104px] pb-16 px-4">
        <div className="max-w-7xl mx-auto space-y-6">
          
          {/* 1. PRE-SCAN STATE (Centered, focused search interface) */}
          {!result && (
            <motion.section
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              className="max-w-2xl mx-auto space-y-6 text-center pt-10 sm:pt-16"
            >
              <div className="rounded-[28px] border border-[#1A3654] bg-gradient-to-br from-[#08111E] via-[#0A1526] to-[#07111F] p-6 sm:p-10 shadow-[0_24px_80px_rgba(0,0,0,0.45)] relative overflow-hidden">
                <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-[#00C2FF]/70 via-[#10B981]/40 to-transparent" />
                
                <div className="flex flex-col items-center mb-8">
                  <div className="h-16 w-16 rounded-2xl bg-[#071321] border border-[#1A3654] flex items-center justify-center shadow-[inset_0_1px_0_rgba(255,255,255,0.08)] mb-4 text-[#00C2FF]">
                    <LinkIcon className="w-8 h-8" />
                  </div>
                  <h1 className="text-3xl sm:text-4xl font-black tracking-tight text-white">Scan a suspicious link</h1>
                  <p className="text-[#98B3CD] mt-2 max-w-md text-sm leading-relaxed">
                    Instantly analyze any web link for zero-day phishing indicators, suspicious redirects, and credential-harvesting triggers.
                  </p>
                </div>

                <div className="space-y-5 text-left">
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-[#6D88A6]">
                      <ScanLine className="w-4.5 h-4.5" />
                    </div>
                    <input
                      type="url"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault();
                          void handleScan();
                        }
                      }}
                      placeholder="https://example.com/login"
                      className="w-full h-14 pl-11 pr-4 rounded-2xl bg-[#050A14] border border-[#1D3555] text-white placeholder:text-[#6E88A4] focus:outline-none focus:border-[#00C2FF] focus:ring-4 focus:ring-[#00C2FF]/10 transition-all"
                    />
                  </div>

                  <div className="flex flex-wrap gap-2 justify-center">
                    {sampleUrls.map((sample) => (
                      <button
                        key={sample}
                        type="button"
                        onClick={() => fillSample(sample)}
                        className="px-3.5 py-1.5 rounded-full text-xs border border-[#1D3555] bg-[#050A14] text-[#A7C1DB] hover:text-white hover:border-[#00C2FF]/45 hover:bg-[#00C2FF]/10 transition-all"
                      >
                        {sample}
                      </button>
                    ))}
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2 pt-2">
                    <button
                      onClick={handleScan}
                      disabled={!trimmedUrl || scanning}
                      className="inline-flex items-center justify-center gap-2 h-12 rounded-xl bg-[#00C2FF] text-[#04101E] font-bold shadow-[0_12px_30px_rgba(0,194,255,0.28)] hover:bg-[#33CCFF] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {scanning ? (
                        <>
                          <Gauge className="w-4 h-4 animate-spin text-[#04101E]" />
                          Scanning...
                        </>
                      ) : (
                        <>
                          <ShieldAlert className="w-4 h-4 text-[#04101E]" />
                          Scan URL
                        </>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={clearForm}
                      className="inline-flex items-center justify-center gap-2 h-12 rounded-xl border border-[#1D3555] bg-[#050A14] text-[#A7C1DB] hover:text-white hover:border-[#00C2FF]/45 hover:bg-[#00C2FF]/10 transition-all"
                    >
                      <Trash2 className="w-4 h-4" />
                      Clear
                    </button>
                  </div>
                </div>
              </div>
            </motion.section>
          )}

          {/* 2. ERROR STATE */}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              className="max-w-2xl mx-auto rounded-2xl border border-red-500/40 bg-red-500/10 p-4 sm:p-5"
            >
              <div className="flex items-start gap-3">
                <XCircle className="w-5 h-5 text-red-300 mt-0.5 shrink-0" />
                <div>
                  <p className="text-red-100 font-semibold">Scan failed</p>
                  <p className="text-red-200/90 text-sm mt-1">{error}</p>
                </div>
              </div>
            </motion.div>
          )}

          {/* 3. POST-SCAN STATE (Polished Security Dashboard) */}
          {result && (
            <motion.section
              initial={{ opacity: 0, y: 18 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-6"
            >
              {/* Top Minimalist Search Bar (for easy re-scanning) */}
              <div className="rounded-2xl border border-[#1A3654] bg-[#08111E]/80 p-4 backdrop-blur-xl flex flex-col md:flex-row items-center gap-4">
                <div className="flex items-center gap-2 text-white/90 shrink-0 font-bold text-sm">
                  <ScanLine className="w-4.5 h-4.5 text-[#00C2FF]" />
                  <span>Scan new URL:</span>
                </div>
                <div className="relative w-full">
                  <input
                    type="url"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        void handleScan();
                      }
                    }}
                    placeholder="Enter URL to scan..."
                    className="w-full h-11 pl-4 pr-24 rounded-xl bg-[#050A14] border border-[#1D3555] text-white placeholder:text-[#6E88A4] focus:outline-none focus:border-[#00C2FF] text-sm"
                  />
                  <div className="absolute right-1 top-1 flex gap-1">
                    <button
                      onClick={handleScan}
                      disabled={!trimmedUrl || scanning}
                      className="px-4 h-9 rounded-lg bg-[#00C2FF] text-[#04101E] text-xs font-bold hover:bg-[#33CCFF] transition-all disabled:opacity-50"
                    >
                      {scanning ? 'Scanning...' : 'Scan'}
                    </button>
                    <button
                      onClick={clearForm}
                      className="px-3 h-9 rounded-lg border border-[#1D3555] text-[#A7C1DB] hover:text-white text-xs"
                    >
                      Reset
                    </button>
                  </div>
                </div>
              </div>

              {/* Main Dashboard Layout */}
              <div className="grid gap-6 lg:grid-cols-[0.85fr_1.15fr] items-start">
                
                {/* Left Column: Verdict & Threat Evidence */}
                <div className="space-y-6">
                  {/* Verdict and Score Card */}
                  <div className={`rounded-[28px] border border-[#1A3654] bg-gradient-to-br ${scoreTone} from-15% p-6 sm:p-8 relative overflow-hidden shadow-lg`}>
                    <div className="flex flex-col items-center text-center">
                      <div className="relative w-36 h-36 rounded-full border-[8px] flex items-center justify-center shadow-lg" style={{ borderColor: getStatusColor(result.status) }}>
                        <div className="absolute inset-2.5 rounded-full bg-[#07111F]/95 flex flex-col items-center justify-center">
                          <div className="flex items-center gap-1.5 mb-0.5" style={{ color: getStatusColor(result.status) }}>
                            {getStatusIcon(result.status)}
                            <span className="text-[10px] uppercase tracking-[0.24em] font-bold">{result.status}</span>
                          </div>
                          <div className="text-4xl font-black text-white leading-none">{result.score}</div>
                          <p className="text-[#9BB5CE] text-[10px] mt-1">out of 100</p>
                        </div>
                      </div>

                      <div className="mt-4 flex items-center gap-2">
                        <h2 className="text-2xl font-black text-white">{result.verdict}</h2>
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold border border-white/10 bg-white/5 text-[#D2E5F5]">
                          {confidencePercent}% Conf.
                        </span>
                      </div>
                      
                      <p className="text-[#D1E0EE] text-sm mt-3 leading-relaxed">{result.explanation}</p>
                    </div>

                    {/* Recommendations Alert Box */}
                    {recommendations.length > 0 && (
                      <div className="mt-5 pt-4 border-t border-white/5 space-y-2 text-left">
                        <p className="text-xs font-bold uppercase tracking-wider text-[#A7C1DB] mb-2">Recommended Actions</p>
                        {recommendations.map((recommendation, idx) => (
                          <div key={idx} className="p-2.5 bg-black/30 border border-white/5 rounded-xl text-xs text-[#D1E0EE] flex items-start gap-2">
                            <span className="text-[#00C2FF] mt-0.5">•</span>
                            <span>{recommendation}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Threat Evidence List Card */}
                  <Panel title="Threat Indicators" icon={<AlertTriangle className="w-4 h-4" />}>
                    <div className="space-y-3">
                      {result.flags && result.flags.length > 0 ? (
                        result.flags.map((flag: string, index: number) => (
                          <div key={index} className="p-3.5 bg-[#06101D] border border-[#1B3557] rounded-xl flex items-start gap-2">
                            <span className="text-[#FF5F56] font-bold mt-0.5">»</span>
                            <p className="text-white text-xs leading-relaxed break-words">{flag}</p>
                          </div>
                        ))
                      ) : (
                        <div className="p-4 bg-[#06101D] border border-[#1B3557] rounded-xl text-center">
                          <p className="text-[#8BA3BC] text-sm">No specific threats detected</p>
                        </div>
                      )}
                    </div>
                  </Panel>
                </div>

                {/* Right Column: Interactive Virtual Sandbox */}
                <div>
                  <VirtualSandbox
                    url={result.url}
                    status={result.status}
                    screenshotUrl={screenshotData?.url}
                    screenshotError={screenshotData?.error}
                    dynamicAnalysis={dynamicAnalysis}
                  />
                </div>

              </div>

              {/* Deep Forensic Report & Technical Metrics */}
              <div className="mt-8">
                <ForensicReport result={result} />
              </div>
            </motion.section>
          )}
        </div>
      </main>
    </div>
  );
}

function DetailCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="p-4 bg-[#06101D] border border-[#1B3557] rounded-xl">
      <p className="text-[#8BA3BC] text-[11px] uppercase tracking-[0.22em] mb-1">{label}</p>
      <p className="text-white font-semibold break-all text-sm leading-relaxed">{value}</p>
    </div>
  );
}

function MiniMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#1B3557] bg-[#06101D] p-4">
      <p className="text-[#8BA3BC] text-[11px] uppercase tracking-[0.22em] mb-1">{label}</p>
      <p className="text-white font-bold text-sm">{value}</p>
    </div>
  );
}

function StatusRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-4 rounded-2xl border border-[#1B3557] bg-[#06101D] p-4">
      <p className="text-[#8BA3BC] text-sm">{label}</p>
      <p className="text-white text-sm font-semibold text-right break-words max-w-[60%]">{value}</p>
    </div>
  );
}

function MetricCard({ label, value, helper }: { label: string; value: string; helper: string }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
      <p className="text-[#8BA3BC] text-[11px] uppercase tracking-[0.22em] mb-1">{label}</p>
      <p className="text-white text-xl font-black">{value}</p>
      <p className="text-[#A7C1DB] text-xs mt-2 leading-relaxed">{helper}</p>
    </div>
  );
}

function Panel({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="rounded-[28px] border border-[#1A3654] bg-[#08111E]/90 p-6 sm:p-8 backdrop-blur-xl">
      <div className="flex items-center gap-2 mb-5">
        <div className="h-9 w-9 rounded-xl bg-[#06101D] border border-[#1B3557] flex items-center justify-center text-[#00C2FF]">
          {icon}
        </div>
        <h3 className="text-xl font-bold text-white">{title}</h3>
      </div>
      {children}
    </section>
  );
}

function SectionBlock({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-6 last:mb-0">
      <h4 className="text-white font-semibold mb-3">{title}</h4>
      {children}
    </div>
  );
}

function Tag({ children }: { children: React.ReactNode }) {
  return <span className="px-3 py-2 bg-[#06101D] border border-[#1B3557] rounded-full text-sm text-[#B9D0E3]">{children}</span>;
}

interface VirtualSandboxProps {
  url: string;
  status: string;
  screenshotUrl?: string;
  screenshotError?: string;
  dynamicAnalysis?: any;
}

export function VirtualSandbox({ url, status, screenshotUrl, screenshotError, dynamicAnalysis }: VirtualSandboxProps) {
  const [activeTab, setActiveTab] = useState<'preview' | 'tls' | 'forms' | 'scripts'>('preview');
  
  const getLockColor = () => {
    switch (status) {
      case 'safe': return 'text-emerald-400';
      case 'suspicious': return 'text-amber-400';
      case 'phishing': return 'text-rose-500';
      default: return 'text-gray-400';
    }
  };

  const getLockIcon = () => {
    switch (status) {
      case 'safe': return <Lock className="w-3.5 h-3.5 shrink-0" />;
      case 'suspicious': return <AlertCircle className="w-3.5 h-3.5 shrink-0" />;
      case 'phishing': return <AlertTriangle className="w-3.5 h-3.5 shrink-0" />;
      default: return <Unlock className="w-3.5 h-3.5 shrink-0" />;
    }
  };

  const getSecurityVerdict = () => {
    switch (status) {
      case 'safe': return 'Secure connection';
      case 'suspicious': return 'Suspicious URL';
      case 'phishing': return 'Phishing warning';
      default: return 'Unverified';
    }
  };

  const tls = dynamicAnalysis?.tls;
  const redirectChain = dynamicAnalysis?.redirect_chain || [];

  return (
    <div className="rounded-[28px] border border-[#1A3654] bg-[#07111F]/90 overflow-hidden shadow-[0_24px_80px_rgba(0,0,0,0.45)] backdrop-blur-xl">
      {/* Mock Browser Header (Chrome Wrapper) */}
      <div className="bg-[#0b1625] px-4 py-3 border-b border-[#1A3654] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        {/* Browser dot controls */}
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-1.5 shrink-0">
            <span className="h-3 w-3 rounded-full bg-[#FF5F56] border border-[#E0443E]/20" />
            <span className="h-3 w-3 rounded-full bg-[#FFBD2E] border border-[#DEA123]/20" />
            <span className="h-3 w-3 rounded-full bg-[#27C93F] border border-[#1AAB29]/20" />
          </div>
          
          {/* Tab Selection */}
          <div className="flex items-center gap-1.5 overflow-x-auto scrollbar-none">
            <button
              onClick={() => setActiveTab('preview')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all shrink-0 ${activeTab === 'preview' ? 'bg-[#152a42] text-white border border-[#1C3A5C]' : 'text-[#8BA3BC] hover:text-white'}`}
            >
              🖼️ Viewport Preview
            </button>
            <button
              onClick={() => setActiveTab('tls')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all shrink-0 ${activeTab === 'tls' ? 'bg-[#152a42] text-white border border-[#1C3A5C]' : 'text-[#8BA3BC] hover:text-white'}`}
            >
              🔒 TLS Certificate
            </button>
            <button
              onClick={() => setActiveTab('forms')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all shrink-0 ${activeTab === 'forms' ? 'bg-[#152a42] text-white border border-[#1C3A5C]' : 'text-[#8BA3BC] hover:text-white'}`}
            >
              📋 Form Inspector ({dynamicAnalysis?.page?.form_count || 0})
            </button>
            <button
              onClick={() => setActiveTab('scripts')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all shrink-0 ${activeTab === 'scripts' ? 'bg-[#152a42] text-white border border-[#1C3A5C]' : 'text-[#8BA3BC] hover:text-white'}`}
            >
              📜 Redirects & Code
            </button>
          </div>
        </div>

        {/* Live Status Badge */}
        <div className="flex items-center gap-2 px-2.5 py-1 rounded-full border border-[#1F3E63] bg-[#08111E] text-xs font-medium text-[#7FB0C4] shrink-0 self-end sm:self-auto">
          <span className="h-1.5 w-1.5 rounded-full bg-[#00C2FF] animate-pulse" />
          Sandbox Active
        </div>
      </div>

      {/* Address Bar */}
      <div className="bg-[#08111E] px-4 py-2.5 border-b border-[#1A3654] flex items-center gap-2">
        <div className="flex items-center gap-1.5 bg-[#050A14] border border-[#152A42] rounded-xl px-3 py-1.5 w-full text-xs">
          <span className={`flex items-center gap-1.5 font-semibold select-none ${getLockColor()}`}>
            {getLockIcon()}
            <span>{getSecurityVerdict()}</span>
          </span>
          <span className="text-gray-500 font-medium">|</span>
          <span className="text-gray-300 truncate tracking-wide select-all font-mono pl-1">{url}</span>
        </div>
      </div>

      {/* Viewport Content */}
      <div className="p-6 bg-[#040810] min-h-[460px] max-h-[640px] overflow-y-auto">
        {activeTab === 'preview' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h4 className="text-white font-bold text-sm tracking-wide">PAGE VIEWPORT VIEW</h4>
              <span className="text-xs text-[#8BA3BC]">Playwright Headless Capture</span>
            </div>
            
            {screenshotUrl ? (
              <div className="rounded-2xl border border-[#1A3654] overflow-hidden bg-black/40 p-2">
                <img
                  src={screenshotUrl}
                  alt="Sandbox Viewport"
                  className="w-full max-h-[500px] object-contain rounded-xl border border-white/5 bg-black"
                  loading="lazy"
                />
              </div>
            ) : (
              <div className="p-12 border border-dashed border-[#1A3654] rounded-2xl text-center">
                <Globe className="w-12 h-12 text-gray-600 mx-auto mb-3" />
                <p className="text-white font-semibold">Screenshot is not available</p>
                {screenshotError && <p className="text-xs text-[#8BA3BC] mt-1">{screenshotError}</p>}
              </div>
            )}
          </div>
        )}

        {activeTab === 'tls' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h4 className="text-white font-bold text-sm tracking-wide">TLS CERTIFICATE VAULT</h4>
              <span className={`text-xs px-2.5 py-1 rounded-full font-bold border ${tls?.available ? 'text-emerald-400 border-emerald-500/20 bg-emerald-500/5' : 'text-amber-400 border-amber-500/20 bg-amber-500/5'}`}>
                {tls?.available ? 'VALID CERTIFICATE' : 'NO CERTIFICATE DETAILS'}
              </span>
            </div>

            {tls?.available ? (
              <div className="grid gap-4 md:grid-cols-2">
                <div className="p-4 bg-[#08111E] border border-[#1A3654] rounded-2xl space-y-3">
                  <div className="flex items-center gap-2 text-white font-bold text-xs uppercase tracking-wider text-[#00C2FF] border-b border-[#1A3654] pb-2">
                    <Calendar className="w-3.5 h-3.5 text-[#00C2FF]" />
                    <span>Validity Status</span>
                  </div>
                  <div className="space-y-1">
                    <p className="text-[#8BA3BC] text-xs">Expires on</p>
                    <p className="text-white text-sm font-semibold">{new Date(tls.expires_at).toLocaleString()}</p>
                  </div>
                  <div className="space-y-1">
                    <p className="text-[#8BA3BC] text-xs">Days Remaining</p>
                    <p className={`text-sm font-black ${tls.days_remaining < 30 ? 'text-red-400 animate-pulse' : 'text-emerald-400'}`}>
                      {tls.days_remaining} Days
                    </p>
                  </div>
                </div>

                <div className="p-4 bg-[#08111E] border border-[#1A3654] rounded-2xl space-y-3">
                  <div className="flex items-center gap-2 text-white font-bold text-xs uppercase tracking-wider text-[#00C2FF] border-b border-[#1A3654] pb-2">
                    <Key className="w-3.5 h-3.5 text-[#00C2FF]" />
                    <span>Certificate Authority (CA)</span>
                  </div>
                  <div className="space-y-1">
                    <p className="text-[#8BA3BC] text-xs">Common Name (CN)</p>
                    <p className="text-white text-sm font-semibold break-all">{tls.subject_common_name || 'n/a'}</p>
                  </div>
                  <div className="space-y-1">
                    <p className="text-[#8BA3BC] text-xs">Issuer</p>
                    <p className="text-white text-sm font-semibold break-all">{tls.issuer_common_name || 'n/a'}</p>
                  </div>
                </div>

                {tls.subject_alt_names && tls.subject_alt_names.length > 0 && (
                  <div className="p-4 bg-[#08111E] border border-[#1A3654] rounded-2xl space-y-3 md:col-span-2">
                    <div className="text-white font-bold text-xs uppercase tracking-wider text-[#00C2FF] border-b border-[#1A3654] pb-2">
                      Subject Alternative Names (SANs)
                    </div>
                    <div className="flex flex-wrap gap-2 max-h-[140px] overflow-y-auto pr-1">
                      {tls.subject_alt_names.map((san: string, idx: number) => (
                        <span key={idx} className="px-2 py-1 bg-[#050A14] border border-[#152A42] rounded-lg text-xs font-mono text-[#7FB0C4] break-all">
                          {san}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-12 border border-dashed border-[#1A3654] rounded-2xl text-center">
                <Unlock className="w-12 h-12 text-amber-500 mx-auto mb-3" />
                <p className="text-white font-semibold">TLS Lookup Failed or Disabled</p>
                <p className="text-xs text-[#8BA3BC] mt-1">
                  {tls?.error || 'No TLS details returned from the scanner. Safe connections are required to extract TLS cert information.'}
                </p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'forms' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h4 className="text-white font-bold text-sm tracking-wide">FORM ACTION ANALYZER</h4>
              <span className={`text-xs px-2.5 py-1 rounded-full font-bold border ${dynamicAnalysis?.page?.form_count > 0 ? 'text-amber-400 border-amber-500/20 bg-amber-500/5' : 'text-emerald-400 border-emerald-500/20 bg-emerald-500/5'}`}>
                {dynamicAnalysis?.page?.form_count || 0} FORMS FOUND
              </span>
            </div>

            {dynamicAnalysis?.page?.form_count > 0 ? (
              <div className="space-y-4">
                <div className="grid gap-4 sm:grid-cols-3">
                  <div className="p-4 bg-[#08111E] border border-[#1A3654] rounded-2xl text-center">
                    <p className="text-[#8BA3BC] text-xs uppercase tracking-wider mb-1">Password Inputs</p>
                    <p className={`text-2xl font-black ${dynamicAnalysis.page.password_field_count > 0 ? 'text-red-400' : 'text-white'}`}>
                      {dynamicAnalysis.page.password_field_count || 0}
                    </p>
                  </div>
                  <div className="p-4 bg-[#08111E] border border-[#1A3654] rounded-2xl text-center">
                    <p className="text-[#8BA3BC] text-xs uppercase tracking-wider mb-1">Hidden Fields</p>
                    <p className="text-2xl font-black text-white">{dynamicAnalysis.page.hidden_input_count || 0}</p>
                  </div>
                  <div className="p-4 bg-[#08111E] border border-[#1A3654] rounded-2xl text-center">
                    <p className="text-[#8BA3BC] text-xs uppercase tracking-wider mb-1">Form Mismatch</p>
                    <p className={`text-2xl font-black ${dynamicAnalysis.page.form_action_mismatch_count > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {dynamicAnalysis.page.form_action_mismatch_count || 0}
                    </p>
                  </div>
                </div>

                {dynamicAnalysis.page.external_form_actions && dynamicAnalysis.page.external_form_actions.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-white text-xs font-semibold uppercase tracking-wider text-red-400">
                      🚨 External Submit Action Targets
                    </div>
                    <div className="space-y-2">
                      {dynamicAnalysis.page.external_form_actions.map((action: string, idx: number) => (
                        <div key={idx} className="p-3.5 bg-red-950/20 border border-red-500/20 rounded-xl flex items-center justify-between gap-3">
                          <span className="text-red-200 text-xs font-mono break-all">{action}</span>
                          <ExternalLink className="w-3.5 h-3.5 text-red-400 shrink-0" />
                        </div>
                      ))}
                    </div>
                    <p className="text-xs text-[#8BA3BC] leading-relaxed">
                      ⚠️ **Form action mismatch:** These forms submit credentials or input data to domains other than the host registrable domain. This is a very common signal in credential harvesting phishing pages.
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-12 border border-dashed border-[#1A3654] rounded-2xl text-center">
                <FileCode className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
                <p className="text-white font-semibold">No Forms Detected</p>
                <p className="text-xs text-[#8BA3BC] mt-1">This page does not capture any user input parameters (like logins or emails).</p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'scripts' && (
          <div className="space-y-6">
            {/* Redirect chain */}
            {redirectChain.length > 0 && (
              <div className="space-y-3">
                <h4 className="text-white font-bold text-sm tracking-wide uppercase">CRAWLER REDIRECT CHAIN</h4>
                <div className="space-y-3.5 relative pl-4 before:absolute before:left-1.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#1A3654]">
                  {redirectChain.map((hop: any, idx: number) => (
                    <div key={idx} className="relative flex items-start gap-3">
                      <span className="absolute -left-[19px] top-1.5 h-3.5 w-3.5 rounded-full border-2 border-[#1A3654] bg-[#040810] flex items-center justify-center">
                        <span className="h-1.5 w-1.5 rounded-full bg-[#00C2FF]" />
                      </span>
                      <div className="p-3 bg-[#08111E] border border-[#1A3654] rounded-xl w-full">
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <span className="text-white text-xs font-bold font-mono">Hop {idx + 1}: HTTP {hop.status_code}</span>
                          <span className="text-xs text-[#7FB0C4]">{hop.host || 'unknown host'}</span>
                        </div>
                        <p className="text-[#8BA3BC] text-xs font-mono break-all mt-1">{hop.url}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Script assets */}
            <div className="space-y-4">
              <h4 className="text-white font-bold text-sm tracking-wide uppercase">SCRIPT ENGINE SIGNATURES</h4>
              
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="p-4 bg-[#08111E] border border-[#1A3654] rounded-2xl">
                  <p className="text-[#8BA3BC] text-xs uppercase tracking-wider mb-1">External Scripts Loaded</p>
                  <p className="text-xl font-black text-white">{dynamicAnalysis?.page?.external_script_count || 0}</p>
                </div>
                <div className="p-4 bg-[#08111E] border border-[#1A3654] rounded-2xl">
                  <p className="text-[#8BA3BC] text-xs uppercase tracking-wider mb-1">iFrames Count</p>
                  <p className="text-xl font-black text-white">{dynamicAnalysis?.page?.iframe_count || 0}</p>
                </div>
              </div>

              {dynamicAnalysis?.page?.suspicious_script_keywords?.length > 0 && (
                <div className="space-y-2">
                  <p className="text-amber-400 text-xs font-semibold uppercase tracking-wider flex items-center gap-1">
                    <Terminal className="w-3.5 h-3.5 text-amber-400" />
                    Suspicious JS Keywords Flagged
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {dynamicAnalysis.page.suspicious_script_keywords.map((kw: string, idx: number) => (
                      <span key={idx} className="px-2.5 py-1 bg-amber-500/10 border border-amber-500/20 rounded-lg text-xs font-mono text-amber-300">
                        {kw}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

interface ForensicReportProps {
  result: UrlScanResult;
}

export function ForensicReport({ result }: ForensicReportProps) {
  const [activeTab, setActiveTab] = useState<'structure' | 'heuristics' | 'threatIntel' | 'riskRegistry'>('structure');
  const [expandedRisks, setExpandedRisks] = useState<number[]>([]);

  const toggleRisk = (index: number) => {
    if (expandedRisks.includes(index)) {
      setExpandedRisks(expandedRisks.filter((i) => i !== index));
    } else {
      setExpandedRisks([...expandedRisks, index]);
    }
  };

  const featureSummary = result.feature_summary || {};
  const analysisDetails = result.analysis_details || {};
  const parsedUrl = analysisDetails.parsed_url || {};
  const threatIntel = analysisDetails.threat_intel || {};
  const riskFactors = analysisDetails.risk_factors || [];

  // Calculate ratios locally to avoid backend dependency
  const urlString = result.url || '';
  const charDiversity = urlString.length > 0 ? Math.round((new Set(urlString).size / urlString.length) * 100) : 0;
  const digitRatio = urlString.length > 0 ? Math.round((urlString.replace(/[^0-9]/g, '').length / urlString.length) * 100) : 0;
  const specialCharRatio = urlString.length > 0 ? Math.round((urlString.replace(/[a-zA-Z0-9]/g, '').length / urlString.length) * 100) : 0;

  // Shannon Entropy and score calculations
  const urlEntropy = Number(featureSummary['url_entropy'] || 0);
  const anomalyScore = Number(featureSummary['anomaly_score'] || 0);
  const urgencyScore = Number(featureSummary['urgency_score'] || 0);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'safe': return '#00D68F';
      case 'suspicious': return '#FFAA00';
      case 'phishing': return '#FF3B3B';
      default: return '#1E3A5F';
    }
  };

  // List of Heuristic Signals
  const heuristicSignals = [
    {
      name: 'HTTPS Encryption Status',
      description: 'Checks if URL uses SSL/TLS. Plaintext HTTP sites are highly vulnerable to interception.',
      status: featureSummary['is_https'] === 1 ? 'safe' : 'fail',
      text: featureSummary['is_https'] === 1 ? 'HTTPS Active' : 'No HTTPS Detected',
    },
    {
      name: 'IP Address Hostname Check',
      description: 'Verifies if an IP literal (e.g. 192.168.1.1) is used as host. Phishing sites use this to hide domain names.',
      status: featureSummary['has_ip'] === 1 ? 'fail' : 'safe',
      text: featureSummary['has_ip'] === 1 ? 'Raw IP Used' : 'Standard Domain Name',
    },
    {
      name: 'Embedded URL Credentials',
      description: 'Detects username or password prefixes inside URL (e.g. user:pass@host). Often used for deception.',
      status: featureSummary['has_credentials'] === 1 ? 'fail' : 'safe',
      text: featureSummary['has_credentials'] === 1 ? 'Credentials Found' : 'No Embedded Credentials',
    },
    {
      name: 'Suspicious TLD Check',
      description: 'Flags top-level domains frequently abused by attackers due to low-cost or minimal validation (e.g. .tk, .ml).',
      status: featureSummary['suspicious_tld'] === 1 ? 'fail' : 'safe',
      text: featureSummary['suspicious_tld'] === 1 ? 'Risky TLD Detected' : 'Safe TLD Profile',
    },
    {
      name: 'Typosquatting & Lookalike Check',
      description: 'Flags domain names containing minor spelling edits or numbers that mimic trusted brands.',
      status: featureSummary['has_typosquatting'] === 1 ? 'fail' : 'safe',
      text: featureSummary['has_typosquatting'] === 1 ? 'Squatting Detected' : 'No Clear Typos',
    },
    {
      name: 'URL Shortener Redirection',
      description: 'Checks if the URL resolves to a known link shortener service to mask the real destination.',
      status: featureSummary['is_shortener'] === 1 ? 'fail' : 'safe',
      text: featureSummary['is_shortener'] === 1 ? 'Shortened Link' : 'Direct / Non-Shortener',
    },
    {
      name: 'Disposable Free Hosting Platform',
      description: 'Flags domains hosted on free tiers (e.g. Vercel, Netlify, Github Pages) used for fast phishing deployments.',
      status: featureSummary['is_free_hosting'] === 1 ? 'fail' : 'safe',
      text: featureSummary['is_free_hosting'] === 1 ? 'Free Host Detected' : 'Self-hosted / Standard host',
    },
    {
      name: 'Non-Standard Network Port',
      description: 'Flags explicit ports (other than standard port 80 or 443) listed inside the URL host.',
      status: featureSummary['has_port'] === 1 ? 'fail' : 'safe',
      text: featureSummary['has_port'] === 1 ? 'Custom Port Open' : 'Standard Port (80/443)',
    },
    {
      name: 'Consecutive Hyphens',
      description: 'Flags domains containing consecutive hyphens (e.g. pay-pal--login) which is highly anomalous.',
      status: featureSummary['consecutive_hyphens'] === 1 ? 'fail' : 'safe',
      text: featureSummary['consecutive_hyphens'] === 1 ? 'Anomalous Hyphens' : 'Normal Character Flow',
    },
    {
      name: 'Service Prefix Impersonation',
      description: 'Flags prefixes like "service-" or "login-" prepended directly to brand names to deceive users.',
      status: featureSummary['has_service_prefix'] === 1 ? 'fail' : 'safe',
      text: featureSummary['has_service_prefix'] === 1 ? 'Deceptive Prefix Found' : 'No Impersonation Prefix',
    },
    {
      name: 'Leet-speak Obfuscation',
      description: 'Flags character swaps using numbers/symbols (e.g. w4ll3t) to sneak past email and security scanners.',
      status: featureSummary['has_leetspeak'] === 1 ? 'fail' : 'safe',
      text: featureSummary['has_leetspeak'] === 1 ? 'Leet-speak Detected' : 'Clean Typography',
    },
    {
      name: 'Homograph IDN Spoofing',
      description: 'Flags internationalized domain names (punycode) containing visual lookalike characters from other scripts.',
      status: featureSummary['has_homograph'] === 1 ? 'fail' : 'safe',
      text: featureSummary['has_homograph'] === 1 ? 'Unicode Spoofing Active' : 'Latin Characters Only',
    },
    {
      name: 'Zero-Day Brand Impersonation',
      description: `Flags fuzzy matches against popular web brands. Match similarity: ${featureSummary['brand_similarity'] ? Math.round(Number(featureSummary['brand_similarity']) * 100) + '%' : '0%'}`,
      status: featureSummary['brand_impersonation'] === 1 ? 'fail' : 'safe',
      text: featureSummary['brand_impersonation'] === 1 ? 'Brand Mimicry Flagged' : 'No Brand Impersonation',
    },
    {
      name: 'Urgency Manipulation Language',
      description: `Flags urgency or threat terms designed to rush victims. Urgency score: ${featureSummary['urgency_score'] ? Math.round(Number(featureSummary['urgency_score']) * 100) + '%' : '0%'}`,
      status: featureSummary['has_urgency_tactics'] === 1 ? 'fail' : 'safe',
      text: featureSummary['has_urgency_tactics'] === 1 ? 'Psychological Tactics Used' : 'No Urgency Cues',
    },
    {
      name: 'Heavy Percent-Encoding',
      description: `Flags URLs containing multiple percent-encoded characters (%xx) to obfuscate paths. Count: ${featureSummary['percent_encoded_count'] || 0}`,
      status: Number(featureSummary['percent_encoded_count'] || 0) >= 3 ? 'fail' : 'safe',
      text: Number(featureSummary['percent_encoded_count'] || 0) >= 3 ? 'Heavy Encoding Found' : 'Clean Path Encoding',
    },
  ];

  return (
    <section className="rounded-[28px] border border-[#1A3654] bg-[#08111E]/90 p-6 sm:p-8 backdrop-blur-xl shadow-[0_24px_80px_rgba(0,0,0,0.45)]">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1A3654] pb-6 mb-6">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-[#06101D] border border-[#1B3557] flex items-center justify-center text-[#00C2FF]">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-xl font-bold text-white">Deep Forensic Report & Technical Metrics</h3>
            <p className="text-[#8BA3BC] text-xs mt-1">Granular inspection breakdown of static heuristics, entropy levels, and feed logs.</p>
          </div>
        </div>

        {/* Tab switcher */}
        <div className="flex items-center gap-1.5 overflow-x-auto scrollbar-none bg-[#050A14] border border-[#1A3654] p-1 rounded-xl shrink-0">
          <button
            onClick={() => setActiveTab('structure')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all shrink-0 flex items-center gap-1.5 ${activeTab === 'structure' ? 'bg-[#1C3A5C] text-[#00C2FF] border border-[#274F7C]' : 'text-[#8BA3BC] hover:text-white'}`}
          >
            <Hash className="w-3.5 h-3.5" />
            Structure & Ratios
          </button>
          <button
            onClick={() => setActiveTab('heuristics')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all shrink-0 flex items-center gap-1.5 ${activeTab === 'heuristics' ? 'bg-[#1C3A5C] text-[#00C2FF] border border-[#274F7C]' : 'text-[#8BA3BC] hover:text-white'}`}
          >
            <Cpu className="w-3.5 h-3.5" />
            Heuristics Check
          </button>
          <button
            onClick={() => setActiveTab('threatIntel')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all shrink-0 flex items-center gap-1.5 ${activeTab === 'threatIntel' ? 'bg-[#1C3A5C] text-[#00C2FF] border border-[#274F7C]' : 'text-[#8BA3BC] hover:text-white'}`}
          >
            <Database className="w-3.5 h-3.5" />
            Threat Intel & ML
          </button>
          <button
            onClick={() => setActiveTab('riskRegistry')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all shrink-0 flex items-center gap-1.5 ${activeTab === 'riskRegistry' ? 'bg-[#1C3A5C] text-[#00C2FF] border border-[#274F7C]' : 'text-[#8BA3BC] hover:text-white'}`}
          >
            <Shield className="w-3.5 h-3.5" />
            Risk Registry ({riskFactors.length})
          </button>
        </div>
      </div>

      {/* Tab Content */}
      <div>
        {/* Tab 1: Structure & Ratios */}
        {activeTab === 'structure' && (
          <div className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2">
              
              {/* URL Breakdown Details */}
              <div className="space-y-4">
                <h4 className="text-white font-bold text-xs uppercase tracking-wider text-[#00C2FF] border-b border-[#1A3654] pb-2">
                  URL Structural Parameters
                </h4>
                
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="p-3 bg-[#06101D] border border-[#1B3557] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">Scheme</p>
                    <p className="text-white text-xs font-mono font-bold">{parsedUrl.scheme || 'n/a'}</p>
                  </div>
                  <div className="p-3 bg-[#06101D] border border-[#1B3557] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">Hostname</p>
                    <p className="text-white text-xs font-mono font-bold truncate" title={parsedUrl.hostname}>{parsedUrl.hostname || 'n/a'}</p>
                  </div>
                  <div className="p-3 bg-[#06101D] border border-[#1B3557] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">Registrable Domain</p>
                    <p className="text-white text-xs font-mono font-bold truncate" title={parsedUrl.base_domain}>{parsedUrl.base_domain || 'n/a'}</p>
                  </div>
                  <div className="p-3 bg-[#06101D] border border-[#1B3557] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">Port</p>
                    <p className="text-white text-xs font-mono font-bold">{parsedUrl.port || 'Default (80/443)'}</p>
                  </div>
                  <div className="p-3 bg-[#06101D] border border-[#1B3557] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">Subdomains</p>
                    <p className="text-white text-xs font-mono font-bold">{featureSummary['num_subdomains'] ?? '0'}</p>
                  </div>
                  <div className="p-3 bg-[#06101D] border border-[#1B3557] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">URL Character Length</p>
                    <p className="text-white text-xs font-mono font-bold">{featureSummary['url_length'] ?? urlString.length} chars</p>
                  </div>
                </div>

                <div className="p-3 bg-[#06101D] border border-[#1B3557] rounded-xl space-y-1">
                  <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider">Path String</p>
                  <p className="text-white text-xs font-mono break-all leading-normal">{parsedUrl.path || '/'}</p>
                </div>

                <div className="p-3 bg-[#06101D] border border-[#1B3557] rounded-xl space-y-1">
                  <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider">Query Parameters</p>
                  <p className="text-white text-xs font-mono break-all leading-normal">{parsedUrl.query || 'None'}</p>
                </div>

                <div className="p-3 bg-[#06101D] border border-[#1B3557] rounded-xl space-y-1">
                  <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider">Fragment Identifier</p>
                  <p className="text-white text-xs font-mono break-all leading-normal">{parsedUrl.fragment || 'None'}</p>
                </div>
              </div>

              {/* Entropy & Ratios Visualization */}
              <div className="space-y-6">
                <div className="space-y-4">
                  <h4 className="text-white font-bold text-xs uppercase tracking-wider text-[#00C2FF] border-b border-[#1A3654] pb-2">
                    Shannon Entropy & Anomaly Score
                  </h4>
                  
                  {/* URL Entropy */}
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-xs font-semibold">
                      <span className="text-[#A7C1DB]">URL Shannon Entropy</span>
                      <span className="text-white font-mono">{urlEntropy.toFixed(4)} / 8.00</span>
                    </div>
                    <div className="h-2 rounded-full bg-[#050A14] overflow-hidden border border-[#1C3657]">
                      <div 
                        className={`h-full transition-all duration-500 rounded-full ${urlEntropy >= 4.8 ? 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]' : urlEntropy >= 4.0 ? 'bg-amber-400' : 'bg-emerald-400'}`}
                        style={{ width: `${(urlEntropy / 8.0) * 100}%` }}
                      />
                    </div>
                    <p className="text-[10px] text-[#8BA3BC] leading-relaxed">
                      Randomness score based on character frequencies. Values above 4.5 indicate high likelihood of auto-generated or obfuscated strings.
                    </p>
                  </div>

                  {/* Anomaly Level */}
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-xs font-semibold">
                      <span className="text-[#A7C1DB]">Statistical Anomaly Score</span>
                      <span className="text-white font-mono">{Math.round(anomalyScore * 100)}%</span>
                    </div>
                    <div className="h-2 rounded-full bg-[#050A14] overflow-hidden border border-[#1C3657]">
                      <div 
                        className={`h-full transition-all duration-500 rounded-full ${anomalyScore >= 0.6 ? 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]' : anomalyScore >= 0.4 ? 'bg-amber-400' : 'bg-emerald-400'}`}
                        style={{ width: `${anomalyScore * 100}%` }}
                      />
                    </div>
                    <p className="text-[10px] text-[#8BA3BC] leading-relaxed">
                      Measures deviation from common top registrable domain structures (character counts, hyphens, prefixes).
                    </p>
                  </div>
                </div>

                <div className="space-y-4">
                  <h4 className="text-white font-bold text-xs uppercase tracking-wider text-[#00C2FF] border-b border-[#1A3654] pb-2">
                    Text Character Distribution Ratios
                  </h4>
                  
                  <div className="grid gap-4 sm:grid-cols-3">
                    {/* Character Diversity */}
                    <div className="space-y-2">
                      <div className="flex justify-between text-[11px] font-bold text-[#A7C1DB]">
                        <span>Diversity</span>
                        <span className="font-mono text-white">{charDiversity}%</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-[#050A14] overflow-hidden border border-[#1A304D]">
                        <div className="h-full bg-cyan-400" style={{ width: `${charDiversity}%` }} />
                      </div>
                      <p className="text-[9px] text-[#8BA3BC] leading-relaxed">Unique character ratio relative to URL length.</p>
                    </div>

                    {/* Digit Ratio */}
                    <div className="space-y-2">
                      <div className="flex justify-between text-[11px] font-bold text-[#A7C1DB]">
                        <span>Digits</span>
                        <span className="font-mono text-white">{digitRatio}%</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-[#050A14] overflow-hidden border border-[#1A304D]">
                        <div className={`h-full ${digitRatio > 15 ? 'bg-amber-400' : 'bg-cyan-400'}`} style={{ width: `${digitRatio}%` }} />
                      </div>
                      <p className="text-[9px] text-[#8BA3BC] leading-relaxed">Numerical ratio. Attackers swap letters for digits (e.g. 0/1).</p>
                    </div>

                    {/* Special Character Ratio */}
                    <div className="space-y-2">
                      <div className="flex justify-between text-[11px] font-bold text-[#A7C1DB]">
                        <span>Special Chars</span>
                        <span className="font-mono text-white">{specialCharRatio}%</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-[#050A14] overflow-hidden border border-[#1A304D]">
                        <div className={`h-full ${specialCharRatio > 20 ? 'bg-amber-400' : 'bg-cyan-400'}`} style={{ width: `${specialCharRatio}%` }} />
                      </div>
                      <p className="text-[9px] text-[#8BA3BC] leading-relaxed">Symbol ratio (hyphens, underscores, slashes) in domain.</p>
                    </div>
                  </div>
                </div>
              </div>

            </div>
          </div>
        )}

        {/* Tab 2: Heuristics Check */}
        {activeTab === 'heuristics' && (
          <div className="space-y-4">
            <h4 className="text-white font-bold text-xs uppercase tracking-wider text-[#00C2FF] border-b border-[#1A3654] pb-2">
              Micro-Heuristic Classifier Signals
            </h4>
            
            <div className="grid gap-4 md:grid-cols-2">
              {heuristicSignals.map((signal, idx) => (
                <div 
                  key={idx} 
                  className={`p-4 rounded-2xl border transition-all ${signal.status === 'fail' 
                    ? 'border-red-500/20 bg-red-950/5 hover:border-red-500/35 hover:bg-red-950/10' 
                    : 'border-[#1C3657] bg-[#06101D]/50 hover:border-[#274E7A] hover:bg-[#06101D]/80'
                  }`}
                >
                  <div className="flex items-center justify-between gap-3 mb-2">
                    <span className="text-white font-bold text-xs tracking-wide">{signal.name}</span>
                    <span className={`px-2.5 py-0.5 rounded-full text-[9px] font-black uppercase tracking-wider border select-none ${signal.status === 'fail'
                      ? 'text-red-400 border-red-500/20 bg-red-500/5 animate-pulse'
                      : 'text-emerald-400 border-emerald-500/20 bg-emerald-500/5'
                    }`}>
                      {signal.text}
                    </span>
                  </div>
                  <p className="text-[#8BA3BC] text-[11px] leading-relaxed">{signal.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 3: Threat Intel & ML */}
        {activeTab === 'threatIntel' && (
          <div className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2">
              
              {/* Machine Learning Model Diagnostics */}
              <div className="p-5 bg-[#06101D] border border-[#1B3557] rounded-2xl space-y-4">
                <div className="flex items-center gap-2 text-white font-bold text-xs uppercase tracking-wider text-[#00C2FF] border-b border-[#1A3654] pb-2">
                  <Cpu className="w-3.5 h-3.5 text-[#00C2FF]" />
                  <span>Machine Learning Ensemble Classifier</span>
                </div>
                
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="p-3 bg-[#08111E] border border-[#1A3654] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">Model Source</p>
                    <p className="text-white text-xs font-semibold truncate" title={analysisDetails.model_source}>{analysisDetails.model_source || 'hybrid_ensemble'}</p>
                  </div>
                  <div className="p-3 bg-[#08111E] border border-[#1A3654] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">Classifier Status</p>
                    <p className="text-white text-xs font-semibold">{analysisDetails.model_status || 'available'}</p>
                  </div>
                  <div className="p-3 bg-[#08111E] border border-[#1A3654] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">Verdict Score</p>
                    <p className="text-white text-xs font-black" style={{ color: getStatusColor(result.status) }}>{result.score} / 100</p>
                  </div>
                  <div className="p-3 bg-[#08111E] border border-[#1A3654] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">System Confidence</p>
                    <p className="text-white text-xs font-black">{Math.round((result.confidence ?? 0) * 100)}%</p>
                  </div>
                </div>

                <div className="p-3.5 bg-black/40 border border-[#1A3654] rounded-xl">
                  <p className="text-xs text-[#8BA3BC] leading-relaxed">
                    🤖 **Classification Logic:** The core combines dynamic browser DOM signals, host registrar status, TLS certificate validity, and structural fuzzy matching.
                  </p>
                </div>
              </div>

              {/* Threat Intelligence Feed Stats */}
              <div className="p-5 bg-[#06101D] border border-[#1B3557] rounded-2xl space-y-4">
                <div className="flex items-center gap-2 text-white font-bold text-xs uppercase tracking-wider text-[#00C2FF] border-b border-[#1A3654] pb-2">
                  <Database className="w-3.5 h-3.5 text-[#00C2FF]" />
                  <span>Threat Intelligence Feed Matches</span>
                </div>
                
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="p-3 bg-[#08111E] border border-[#1A3654] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">Feed Status</p>
                    <span className={`px-2 py-0.5 rounded-full text-[9px] font-black uppercase tracking-wider border inline-block ${threatIntel.matched
                      ? 'text-red-400 border-red-500/20 bg-red-500/5'
                      : 'text-emerald-400 border-emerald-500/20 bg-emerald-500/5'
                    }`}>
                      {threatIntel.matched ? 'MATCHED / RISKY' : 'NO FEED MATCH'}
                    </span>
                  </div>
                  <div className="p-3 bg-[#08111E] border border-[#1A3654] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">Threat Score Boost</p>
                    <p className="text-white text-xs font-black">+{threatIntel.score_boost || 0} pts</p>
                  </div>
                  <div className="p-3 bg-[#08111E] border border-[#1A3654] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">Domain Age</p>
                    <p className="text-white text-xs font-semibold">{threatIntel.domain_age_days !== undefined && threatIntel.domain_age_days !== null ? `${threatIntel.domain_age_days} Days` : 'n/a'}</p>
                  </div>
                  <div className="p-3 bg-[#08111E] border border-[#1A3654] rounded-xl">
                    <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-1">ASN Reputation</p>
                    <p className="text-white text-xs font-semibold uppercase">{threatIntel.asn_reputation || 'neutral'}</p>
                  </div>
                </div>

                {threatIntel.evidence && threatIntel.evidence.length > 0 && (
                  <div className="p-3 bg-red-950/10 border border-red-500/20 rounded-xl space-y-1">
                    <p className="text-red-300 text-[10px] uppercase tracking-wider font-bold">Threat Feed Evidence Log</p>
                    <ul className="list-disc pl-4 space-y-1">
                      {threatIntel.evidence.map((ev: string, idx: number) => (
                        <li key={idx} className="text-[#D1E0EE] text-xs font-mono">{ev}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

            </div>
          </div>
        )}

        {/* Tab 4: Risk Registry */}
        {activeTab === 'riskRegistry' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-[#1A3654] pb-2">
              <h4 className="text-white font-bold text-xs uppercase tracking-wider text-[#00C2FF]">
                Detailed Technical Risk Registry
              </h4>
              <span className="text-xs text-[#8BA3BC]">{riskFactors.length} issues identified</span>
            </div>

            {riskFactors.length > 0 ? (
              <div className="space-y-3">
                {riskFactors.map((factor: any, idx: number) => {
                  const isExpanded = expandedRisks.includes(idx);
                  const severityColors = {
                    high: 'text-red-400 border-red-500/20 bg-red-500/5',
                    medium: 'text-amber-400 border-amber-500/20 bg-amber-500/5',
                    low: 'text-cyan-400 border-cyan-500/20 bg-cyan-500/5',
                  };
                  return (
                    <div 
                      key={idx} 
                      className="border border-[#1A3654] bg-[#06101D] rounded-2xl overflow-hidden transition-all duration-300"
                    >
                      <button
                        onClick={() => toggleRisk(idx)}
                        className="w-full px-5 py-4 flex items-center justify-between gap-4 text-left hover:bg-[#091728] transition-all"
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <span className={`px-2.5 py-0.5 rounded-full text-[9px] font-black uppercase tracking-wider border select-none shrink-0 ${severityColors[factor.severity as keyof typeof severityColors] || severityColors.low}`}>
                            {factor.severity}
                          </span>
                          <span className="px-2 py-0.5 bg-[#08111E] border border-[#1B3557] rounded-md text-[9px] uppercase font-bold text-[#A7C1DB] shrink-0">
                            {factor.category}
                          </span>
                          <span className="text-white font-bold text-xs truncate">{factor.title}</span>
                        </div>
                        {isExpanded ? (
                          <ChevronUp className="w-4 h-4 text-[#8BA3BC] shrink-0" />
                        ) : (
                          <ChevronDown className="w-4 h-4 text-[#8BA3BC] shrink-0" />
                        )}
                      </button>

                      {isExpanded && (
                        <div className="px-5 pb-5 pt-2 border-t border-[#1A3654] bg-[#050A14]/70 space-y-4">
                          <div className="space-y-1">
                            <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider font-bold">Detected Technical Trace / Evidence</p>
                            <p className="text-white text-xs font-mono leading-relaxed bg-[#06101D] border border-[#1A3654] p-3 rounded-xl break-all">
                              {factor.evidence}
                            </p>
                          </div>
                          <div className="space-y-1">
                            <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider font-bold">Potential Threat Impact</p>
                            <p className="text-white text-xs leading-relaxed bg-[#06101D] border border-[#1A3654] p-3 rounded-xl">
                              {factor.impact}
                            </p>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-12 border border-dashed border-[#1A3654] rounded-2xl text-center">
                <ShieldCheck className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
                <p className="text-white font-semibold">Clean Security Assessment</p>
                <p className="text-xs text-[#8BA3BC] mt-1">No risk registry items found. The model did not trigger any structural or dynamic indicators of phishing.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}


