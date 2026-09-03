import { motion, AnimatePresence } from 'motion/react';
import {
  Shield,
  Link as LinkIcon,
  AlertTriangle,
  CheckCircle,
  Clock,
  ArrowLeft,
  RefreshCw,
  Eye,
  Scale,
  X,
  Lock,
  Unlock,
  Gauge,
  Activity,
  Hash,
  Sparkles,
  LogOut,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../services/api';
import logo from '@/assets/eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png';

interface HistoricalScan {
  url: string;
  score: number;
  verdict: string;
  status: string;
  scanned_at: string;
  feature_summary: Record<string, string | number | boolean>;
  flags: string[];
  explanation: string;
  screenshot?: any;
  analysis_details?: any;
}

export function History() {
  const [scans, setScans] = useState<HistoricalScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rescanningUrl, setRescanningUrl] = useState<string | null>(null);
  const [selectedForComparison, setSelectedForComparison] = useState<HistoricalScan[]>([]);
  const [isCompareOpen, setIsCompareOpen] = useState(false);
  const navigate = useNavigate();
  const { logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const fetchHistory = async (showLoading = true) => {
    try {
      if (showLoading) setLoading(true);
      setError(null);
      const data = await api.getScanHistory();
      setScans(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch scan history');
    } finally {
      if (showLoading) setLoading(false);
    }
  };

  useEffect(() => {
    void fetchHistory();
  }, []);

  const handleViewReport = (scan: HistoricalScan) => {
    // Reconstruct UrlScanResult object to store in sessionStorage
    const scanResult = {
      scan_id: 'cached-history-report',
      url: scan.url,
      score: scan.score,
      confidence: scan.analysis_details?.confidence ?? 0.85,
      verdict: scan.verdict,
      status: scan.status,
      flags: scan.flags,
      feature_summary: scan.feature_summary,
      analysis_details: scan.analysis_details,
      explanation: scan.explanation,
      screenshot: scan.screenshot,
    };

    sessionStorage.setItem('darkhook_latest_url_scan_result', JSON.stringify(scanResult));
    navigate('/scan/url');
  };

  const handleRescan = async (targetUrl: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setRescanningUrl(targetUrl);
    try {
      await api.scanUrl(targetUrl);
      await fetchHistory(false);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Rescan failed');
    } finally {
      setRescanningUrl(null);
    }
  };

  const handleSelectCompare = (scan: HistoricalScan) => {
    if (selectedForComparison.some((s) => s.url === scan.url)) {
      setSelectedForComparison(selectedForComparison.filter((s) => s.url !== scan.url));
    } else {
      if (selectedForComparison.length >= 2) {
        // Replace the second item or keep limit
        setSelectedForComparison([selectedForComparison[0], scan]);
      } else {
        setSelectedForComparison([...selectedForComparison, scan]);
      }
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'safe':
        return '#00D68F';
      case 'suspicious':
        return '#FFAA00';
      case 'phishing':
        return '#FF3B3B';
      default:
        return '#8BA3BC';
    }
  };

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
              <p className="text-sm text-white/90 font-semibold">Live Threat History</p>
            </div>
          </Link>

          <div className="flex items-center gap-3">
            <Link
              to="/dashboard"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-[#1C3657] bg-white/5 text-[#A7C1DB] hover:text-white hover:border-[#00C2FF]/50 hover:bg-[#00C2FF]/10 transition-all text-xs sm:text-sm"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Dashboard</span>
            </Link>
            <button
              onClick={handleLogout}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-[#1C3657] bg-white/5 text-[#A7C1DB] hover:text-white hover:border-[#00C2FF]/50 hover:bg-[#00C2FF]/10 transition-all text-xs sm:text-sm"
            >
              <LogOut className="w-4 h-4" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </nav>

      {/* Content */}
      <main className="relative z-10 max-w-6xl mx-auto px-4 pt-[104px] pb-24">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8"
        >
          <div>
            <h1 className="text-3xl sm:text-4xl font-black tracking-tight text-white">
              Scan <span className="text-[#00C2FF]">History Log</span>
            </h1>
            <p className="text-[#8BA3BC] text-sm mt-1">Audit log of all URL security scans stored in cache repository.</p>
          </div>

          <button
            onClick={() => void fetchHistory(true)}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl border border-[#1C3657] bg-[#07111F] text-xs font-semibold text-[#8BA3BC] hover:text-white hover:border-[#00C2FF] transition-all self-start sm:self-auto"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Log
          </button>
        </motion.div>

        {/* Selected Scans for Comparison Banner */}
        {selectedForComparison.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-6 p-4 rounded-2xl border border-[#00C2FF]/30 bg-[#00C2FF]/5 flex items-center justify-between gap-4 flex-wrap"
          >
            <div className="flex items-center gap-3">
              <Scale className="w-5 h-5 text-[#00C2FF]" />
              <div>
                <p className="text-white text-sm font-semibold">URL Threat Comparison</p>
                <p className="text-xs text-[#8BA3BC]">
                  {selectedForComparison.length === 1
                    ? 'Select 1 more URL to compare side-by-side'
                    : '2 URLs selected. Ready to compare technical metrics.'}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setSelectedForComparison([])}
                className="px-3 py-1.5 rounded-lg border border-white/10 hover:bg-white/5 text-xs text-[#A7C1DB] hover:text-white transition-all"
              >
                Clear
              </button>
              <button
                onClick={() => setIsCompareOpen(true)}
                disabled={selectedForComparison.length < 2}
                className="px-4 py-1.5 rounded-lg bg-[#00C2FF] text-[#04101E] text-xs font-bold hover:bg-[#33CCFF] transition-all disabled:opacity-50"
              >
                Compare Scans
              </button>
            </div>
          </motion.div>
        )}

        {/* Scan Log List */}
        {loading ? (
          <div className="py-24 text-center">
            <RefreshCw className="w-12 h-12 text-[#00C2FF] animate-spin mx-auto mb-4" />
            <p className="text-[#8BA3BC] text-sm">Loading historical scans from MongoDB...</p>
          </div>
        ) : error ? (
          <div className="p-8 border border-red-500/20 bg-red-950/10 rounded-2xl text-center">
            <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-3" />
            <p className="text-red-200 font-semibold mb-1">Failed to read scan logs</p>
            <p className="text-red-300/80 text-xs mb-4">{error}</p>
            <button
              onClick={() => void fetchHistory()}
              className="px-4 py-2 bg-red-500/20 border border-red-500/40 text-red-200 text-xs font-semibold rounded-lg"
            >
              Retry
            </button>
          </div>
        ) : scans.length === 0 ? (
          <div className="border border-[#1A3654] bg-[#08111E]/80 rounded-[28px] p-16 text-center">
            <Clock className="w-16 h-16 text-gray-700 mx-auto mb-4" />
            <h3 className="text-xl font-bold text-white mb-2">No scans recorded yet</h3>
            <p className="text-[#8BA3BC] text-sm max-w-sm mx-auto mb-6">
              When you scan suspect links on the URL Analysis console, they will be archived here.
            </p>
            <Link
              to="/scan/url"
              className="inline-flex items-center gap-2 px-6 py-3 bg-[#00C2FF] text-[#04101E] font-bold rounded-xl shadow-lg hover:bg-[#33CCFF] transition-all"
            >
              Scan a link now
            </Link>
          </div>
        ) : (
          <div className="space-y-3.5">
            {scans.map((scan, idx) => {
              const isSelected = selectedForComparison.some((s) => s.url === scan.url);
              return (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 16 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.04 }}
                  onClick={() => handleViewReport(scan)}
                  className="group relative border border-[#1A3654] bg-[#08111E]/95 hover:bg-[#0b1729] rounded-2xl p-4 sm:p-5 flex items-center justify-between gap-4 cursor-pointer transition-all duration-300 hover:shadow-[0_8px_30px_rgba(0,0,0,0.4)]"
                >
                  <div className="flex items-center gap-4 min-w-0">
                    {/* Checkbox for comparison */}
                    <div 
                      onClick={(e) => {
                        e.stopPropagation();
                        handleSelectCompare(scan);
                      }}
                      className="p-1 cursor-pointer shrink-0"
                    >
                      <div className={`w-4 h-4 rounded border flex items-center justify-center transition-all ${isSelected ? 'border-[#00C2FF] bg-[#00C2FF]/10' : 'border-[#1C3657] hover:border-gray-500'}`}>
                        {isSelected && <div className="w-2 h-2 rounded bg-[#00C2FF]" />}
                      </div>
                    </div>

                    {/* Icon */}
                    <div className="h-10 w-10 rounded-xl bg-[#050A14] border border-[#1A304D] flex items-center justify-center text-[#00C2FF] shrink-0">
                      <LinkIcon className="w-5 h-5" />
                    </div>

                    {/* URL details */}
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="text-[10px] font-black uppercase tracking-wider text-[#00C2FF]">URL</span>
                        <span className="text-gray-600 text-[10px]">•</span>
                        <span className="text-[#8BA3BC] text-xs font-mono">
                          {new Date(scan.scanned_at).toLocaleString()}
                        </span>
                      </div>
                      <p className="text-white text-sm font-semibold truncate font-mono tracking-wide" title={scan.url}>
                        {scan.url}
                      </p>
                    </div>
                  </div>

                  {/* Actions & Score */}
                  <div className="flex items-center gap-4 shrink-0">
                    
                    {/* Rescan Button */}
                    <button
                      onClick={(e) => void handleRescan(scan.url, e)}
                      disabled={rescanningUrl === scan.url}
                      className="p-2.5 rounded-lg border border-[#1A3654] bg-[#050A14] text-[#A7C1DB] hover:text-[#00C2FF] hover:border-[#00C2FF]/40 transition-all shrink-0 hidden sm:inline-block"
                      title="Run a fresh analysis"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${rescanningUrl === scan.url ? 'animate-spin text-[#00C2FF]' : ''}`} />
                    </button>

                    {/* Score Badge */}
                    <div className="text-right">
                      <div 
                        className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border text-xs font-black select-none"
                        style={{ 
                          color: getStatusColor(scan.status),
                          borderColor: `${getStatusColor(scan.status)}30`,
                          backgroundColor: `${getStatusColor(scan.status)}08`
                        }}
                      >
                        <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: getStatusColor(scan.status) }} />
                        <span>{scan.score} ({scan.verdict})</span>
                      </div>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        )}
      </main>

      {/* Comparison Modal */}
      <AnimatePresence>
        {isCompareOpen && selectedForComparison.length === 2 && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-[#040810]/95 backdrop-blur-md overflow-y-auto px-4 py-8"
          >
            <div className="max-w-5xl mx-auto border border-[#1A3654] bg-[#07111F] rounded-[28px] overflow-hidden shadow-[0_24px_80px_rgba(0,0,0,0.8)] relative">
              
              {/* Header */}
              <div className="p-6 border-b border-[#1A3654] flex items-center justify-between bg-[#0b1625]">
                <div className="flex items-center gap-3">
                  <Scale className="w-6 h-6 text-[#00C2FF]" />
                  <div>
                    <h3 className="text-xl font-bold text-white">Security Comparison Console</h3>
                    <p className="text-xs text-[#8BA3BC]">Side-by-side analysis of two audited URLs.</p>
                  </div>
                </div>
                <button
                  onClick={() => setIsCompareOpen(false)}
                  className="h-10 w-10 rounded-xl bg-[#050A14] border border-[#1A3654] flex items-center justify-center text-gray-400 hover:text-white hover:border-[#00C2FF]/30 transition-all"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Grid content */}
              <div className="p-6 space-y-6">
                
                {/* URLs Row */}
                <div className="grid gap-6 md:grid-cols-2">
                  <CompareTargetCard label="Audit Subject A" scan={selectedForComparison[0]} color={getStatusColor(selectedForComparison[0].status)} />
                  <CompareTargetCard label="Audit Subject B" scan={selectedForComparison[1]} color={getStatusColor(selectedForComparison[1].status)} />
                </div>

                {/* Score and Gauge Row */}
                <div className="grid gap-6 md:grid-cols-2 border-t border-[#1A3654] pt-6">
                  <CompareGaugeCard scan={selectedForComparison[0]} color={getStatusColor(selectedForComparison[0].status)} />
                  <CompareGaugeCard scan={selectedForComparison[1]} color={getStatusColor(selectedForComparison[1].status)} />
                </div>

                {/* Statistical Anatomy Metrics */}
                <div className="border-t border-[#1A3654] pt-6 space-y-4">
                  <h4 className="text-[#00C2FF] font-bold text-xs uppercase tracking-wider text-center">
                    Structural & Text Statistics
                  </h4>
                  
                  <div className="grid gap-4 md:grid-cols-3">
                    <CompareMetricWidget 
                      label="Shannon Entropy"
                      helper="Higher = Obfuscated"
                      valA={Number(selectedForComparison[0].feature_summary['url_entropy'] || 0).toFixed(4)}
                      valB={Number(selectedForComparison[1].feature_summary['url_entropy'] || 0).toFixed(4)}
                    />
                    <CompareMetricWidget 
                      label="Character Length"
                      helper="Longer = Suspicious"
                      valA={`${selectedForComparison[0].feature_summary['url_length'] || selectedForComparison[0].url.length} chars`}
                      valB={`${selectedForComparison[1].feature_summary['url_length'] || selectedForComparison[1].url.length} chars`}
                    />
                    <CompareMetricWidget 
                      label="Subdomain Depth"
                      helper="More levels = Obfuscation"
                      valA={`${selectedForComparison[0].feature_summary['num_subdomains'] ?? 0} levels`}
                      valB={`${selectedForComparison[1].feature_summary['num_subdomains'] ?? 0} levels`}
                    />
                  </div>
                </div>

                {/* Specific Risk Flags Check */}
                <div className="border-t border-[#1A3654] pt-6 space-y-4">
                  <h4 className="text-[#00C2FF] font-bold text-xs uppercase tracking-wider text-center">
                    Heuristic Signatures Flagged
                  </h4>
                  
                  <div className="grid gap-6 md:grid-cols-2">
                    <CompareFlagsCard scan={selectedForComparison[0]} color={getStatusColor(selectedForComparison[0].status)} />
                    <CompareFlagsCard scan={selectedForComparison[1]} color={getStatusColor(selectedForComparison[1].status)} />
                  </div>
                </div>

              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function CompareTargetCard({ label, scan, color }: { label: string; scan: HistoricalScan; color: string }) {
  return (
    <div className="p-5 bg-[#06101D] border border-[#1B3557] rounded-2xl relative overflow-hidden">
      <div 
        className="absolute top-0 left-0 w-1.5 h-full" 
        style={{ backgroundColor: color }}
      />
      <p className="text-[#8BA3BC] text-[10px] uppercase tracking-wider mb-2 font-black">{label}</p>
      <p className="text-white text-xs font-mono font-semibold break-all leading-normal">{scan.url}</p>
      <p className="text-[10px] text-[#A7C1DB] mt-2 font-mono">Scanned at: {new Date(scan.scanned_at).toLocaleString()}</p>
    </div>
  );
}

function CompareGaugeCard({ scan, color }: { scan: HistoricalScan; color: string }) {
  return (
    <div className="p-6 bg-[#06101D] border border-[#1B3557] rounded-2xl text-center flex flex-col items-center justify-center">
      <div 
        className="w-24 h-24 rounded-full border-4 flex items-center justify-center mb-3 shadow-[0_0_20px_rgba(0,0,0,0.3)]"
        style={{ 
          borderColor: color,
          boxShadow: `inset 0 0 12px ${color}15, 0 0 20px ${color}10` 
        }}
      >
        <div className="flex flex-col items-center">
          <span className="text-2xl font-black text-white">{scan.score}</span>
          <span className="text-[9px] uppercase tracking-wider text-[#8BA3BC]">score</span>
        </div>
      </div>
      <h5 className="text-lg font-bold uppercase tracking-wider text-white">{scan.verdict}</h5>
      <p className="text-xs text-[#8BA3BC] mt-1 max-w-xs">{scan.explanation || 'No verdict explanation logged'}</p>
    </div>
  );
}

function CompareMetricWidget({ label, helper, valA, valB }: { label: string; helper: string; valA: string | number; valB: string | number }) {
  return (
    <div className="p-4 bg-[#06101D] border border-[#1B3557] rounded-2xl text-center space-y-2">
      <p className="text-[#8BA3BC] text-xs font-bold uppercase tracking-wider">{label}</p>
      
      <div className="grid grid-cols-2 gap-4 border-t border-[#152A42] pt-2">
        <div className="border-r border-[#152A42] pr-2">
          <p className="text-[9px] text-[#8BA3BC] uppercase">Subject A</p>
          <p className="text-white text-sm font-mono font-bold mt-1">{valA}</p>
        </div>
        <div className="pl-2">
          <p className="text-[9px] text-[#8BA3BC] uppercase">Subject B</p>
          <p className="text-white text-sm font-mono font-bold mt-1">{valB}</p>
        </div>
      </div>
      <p className="text-[9px] text-gray-500 italic mt-1">{helper}</p>
    </div>
  );
}

function CompareFlagsCard({ scan, color }: { scan: HistoricalScan; color: string }) {
  return (
    <div className="p-5 bg-[#06101D] border border-[#1B3557] rounded-2xl min-h-[160px]">
      <h5 className="text-white font-bold text-xs uppercase tracking-wider text-[#A7C1DB] border-b border-[#1A3654] pb-2 mb-3">
        Risk Flags list
      </h5>
      <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
        {scan.flags && scan.flags.length > 0 ? (
          scan.flags.map((flag: string, index: number) => (
            <div key={index} className="p-2.5 bg-[#050A14] border border-[#1A3654] rounded-xl flex items-start gap-2">
              <span className="text-[#FF5F56] font-bold mt-0.5 shrink-0">»</span>
              <p className="text-white text-[11px] leading-relaxed break-words">{flag}</p>
            </div>
          ))
        ) : (
          <div className="text-center py-6">
            <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
            <p className="text-[#8BA3BC] text-xs">No risky signatures flagged.</p>
          </div>
        )}
      </div>
    </div>
  );
}