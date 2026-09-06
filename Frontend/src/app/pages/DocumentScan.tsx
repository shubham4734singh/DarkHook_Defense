import { motion, AnimatePresence } from 'motion/react';
import {
  Shield,
  FileText,
  Upload,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ArrowLeft,
  LogOut,
  Copy,
  Check,
  ExternalLink,
  Download,
  Printer,
  Layers,
  Search,
  Globe,
  Crosshair,
  FileCode,
  Terminal,
  Activity,
  Cpu,
} from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { useAuth } from '../contexts/AuthContext';
import { api, type DocumentScanResult } from '../services/api';
import logo from '@/assets/eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png';

export function DocumentScan() {
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<DocumentScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'threats' | 'mitre' | 'urls' | 'logs'>('overview');
  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedLogs, setCopiedLogs] = useState(false);
  const [logFilter, setLogFilter] = useState('');

  const navigate = useNavigate();
  const { logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const handleScan = async () => {
    if (!file) return;

    setScanning(true);
    setError(null);

    try {
      const data = await api.scanDocument(file);
      setResult(data);
      setActiveTab('overview');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred while scanning');
      console.error('Scan error:', err);
    } finally {
      setScanning(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFile = e.target.files?.[0];
    if (uploadedFile) {
      setFile(uploadedFile);
      setError(null);
      setResult(null);
    }
  };

  const copyToClipboard = (text: string, type: 'hash' | 'logs') => {
    navigator.clipboard.writeText(text);
    if (type === 'hash') {
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    } else {
      setCopiedLogs(true);
      setTimeout(() => setCopiedLogs(false), 2000);
    }
  };

  const handleExportJson = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `DarkHook_Report_${result.fileName}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDeepScanUrl = (targetUrl: string) => {
    navigate('/scan/url', { state: { prefillUrl: targetUrl } });
  };

  const getVerdictColor = (verdict: string) => {
    const normalized = (verdict || '').toLowerCase();
    if (normalized.includes('safe')) return '#00D68F';
    if (normalized.includes('suspicious')) return '#FFAA00';
    if (normalized.includes('phishing')) return '#FF3B3B';
    return '#00C2FF';
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-[#FF3B3B]/15 text-[#FF3B3B] border-[#FF3B3B]/30';
      case 'danger':
        return 'bg-[#FF6633]/15 text-[#FF6633] border-[#FF6633]/30';
      case 'warning':
        return 'bg-[#FFAA00]/15 text-[#FFAA00] border-[#FFAA00]/30';
      default:
        return 'bg-[#00D68F]/15 text-[#00D68F] border-[#00D68F]/30';
    }
  };

  const filteredLogs = result?.details.filter((line) =>
    line.toLowerCase().includes(logFilter.toLowerCase())
  ) || [];

  return (
    <div className="min-h-screen bg-[#060D1A] text-slate-200">
      {/* Navbar */}
      <nav className="fixed top-0 left-0 right-0 z-50 h-[68px] bg-[#0D1F38]/95 backdrop-blur-xl border-b border-[#1E3A5F]">
        <div className="max-w-[1440px] mx-auto px-4 h-full flex items-center justify-between">
          <Link to="/dashboard" className="flex items-center gap-2 cursor-pointer">
            <img src={logo} alt="DarkHook Defense" className="h-12" />
          </Link>

          <div className="flex items-center gap-6">
            <Link
              to="/dashboard"
              className="flex items-center gap-2 text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span className="hidden sm:inline font-medium">Dashboard</span>
            </Link>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-4 py-2 text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span className="hidden sm:inline font-medium">Logout</span>
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="pt-[96px] pb-20 px-4">
        <div className="max-w-5xl mx-auto">
          {/* Header */}
          <div className="mb-8 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 bg-[#0D1F38] rounded-2xl flex items-center justify-center border border-[#1E3A5F] shadow-lg shadow-[#00C2FF]/10">
                <FileText className="w-7 h-7 text-[#00C2FF]" />
              </div>
              <div>
                <h1 className="text-3xl font-extrabold text-white tracking-tight">Enterprise Document Scanner</h1>
                <p className="text-[#8BA3BC] text-sm mt-1">
                  17-Layer Deep Static & Macro Analysis with MITRE ATT&CK Mapping
                </p>
              </div>
            </div>

            {/* Quick Badge */}
            <div className="hidden lg:flex items-center gap-2 px-4 py-2 bg-[#0D1F38] border border-[#1E3A5F] rounded-xl text-xs text-[#8BA3BC]">
              <Cpu className="w-4 h-4 text-[#00C2FF]" />
              <span>Zip-Bomb & Magic-Byte Protected</span>
            </div>
          </div>

          {/* Upload Card */}
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-6 md:p-8 mb-8 shadow-xl"
          >
            <div className="mb-6">
              <label className="block text-white font-semibold mb-2">
                Select or Drop File to Inspect
              </label>
              <p className="text-xs text-[#8BA3BC] mb-4">
                Supported: PDF, Word (<span className="text-[#00C2FF]">.docx, .docm, .doc, .rtf</span>), Excel (<span className="text-[#00C2FF]">.xlsx, .xlsm, .xlsb</span>), PowerPoint (<span className="text-[#00C2FF]">.pptx, .ppt, .pps</span>), and Images (<span className="text-[#00C2FF]">.png, .jpg, .webp</span>). Max 10MB.
              </p>

              <div className="relative">
                <input
                  type="file"
                  accept=".pdf,.doc,.docx,.docm,.dotm,.dotx,.xls,.xlsx,.xlsm,.xlsb,.xltm,.xltx,.ppt,.pptx,.pptm,.pps,.ppsx,.png,.jpg,.jpeg,.webp,.bmp,.tif,.tiff"
                  onChange={handleFileUpload}
                  className="hidden"
                  id="document-upload"
                />
                <label
                  htmlFor="document-upload"
                  className="flex flex-col items-center justify-center gap-3 px-4 py-8 sm:px-6 sm:py-10 bg-[#060D1A] border-2 border-dashed border-[#1E3A5F] rounded-xl cursor-pointer hover:border-[#00C2FF] hover:bg-[#0D1F38]/40 transition-all group"
                >
                  <div className="w-14 h-14 rounded-full bg-[#0D1F38] border border-[#1E3A5F] flex items-center justify-center group-hover:border-[#00C2FF] group-hover:scale-110 transition-all">
                    <Upload className="w-6 h-6 text-[#00C2FF]" />
                  </div>
                  <div className="text-center">
                    <p className="text-white font-medium text-base mb-1">
                      {file ? file.name : 'Click to select or drag document here'}
                    </p>
                    <p className="text-[#8BA3BC] text-xs">
                      Deobfuscates embedded VBA, PowerShell, QR codes & formula injections
                    </p>
                  </div>
                </label>
              </div>
            </div>

            {file && (
              <div className="mb-6 p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-xl flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <FileCode className="w-6 h-6 text-[#00C2FF]" />
                  <div>
                    <p className="text-white font-medium text-sm truncate max-w-[280px] sm:max-w-md">{file.name}</p>
                    <p className="text-[#8BA3BC] text-xs">{(file.size / 1024).toFixed(2)} KB • Ready for scan</p>
                  </div>
                </div>
                <button
                  onClick={() => {
                    setFile(null);
                    setError(null);
                    setResult(null);
                  }}
                  className="text-[#FF3B3B] hover:text-[#ff6666] text-xs font-semibold px-3 py-1.5 rounded-lg border border-[#FF3B3B]/30 hover:bg-[#FF3B3B]/10 transition-all"
                >
                  Remove
                </button>
              </div>
            )}

            {error && (
              <div className="mb-6 p-4 bg-[#FF3B3B]/10 border border-[#FF3B3B]/40 rounded-xl flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-[#FF3B3B] flex-shrink-0" />
                <p className="text-[#FF3B3B] text-sm font-medium">{error}</p>
              </div>
            )}

            <button
              onClick={handleScan}
              disabled={!file || scanning}
              className="w-full py-3.5 bg-[#00C2FF] hover:bg-[#00A8E0] text-[#060D1A] font-bold text-base rounded-xl transition-all disabled:opacity-40 disabled:cursor-not-allowed shadow-[0_0_24px_rgba(0,194,255,0.35)] flex items-center justify-center gap-2"
            >
              {scanning ? (
                <>
                  <Activity className="w-5 h-5 animate-spin" />
                  <span>Analyzing Heuristics & Unmasking Payloads...</span>
                </>
              ) : (
                <>
                  <Shield className="w-5 h-5" />
                  <span>Scan Document</span>
                </>
              )}
            </button>
          </motion.div>

          {/* Results Display */}
          {result && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-6"
            >
              {/* Header Action Bar */}
              <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-2">
                  <span className="text-xs uppercase tracking-wider text-[#8BA3BC] font-semibold">Report Generated:</span>
                  <span className="text-xs text-white font-mono">{new Date().toLocaleTimeString()}</span>
                </div>

                <div className="flex items-center gap-3">
                  <button
                    onClick={handleExportJson}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-[#060D1A] border border-[#1E3A5F] hover:border-[#00C2FF] text-[#8BA3BC] hover:text-white rounded-lg text-xs font-medium transition-all"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Export JSON</span>
                  </button>
                  <button
                    onClick={() => window.print()}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-[#060D1A] border border-[#1E3A5F] hover:border-[#00C2FF] text-[#8BA3BC] hover:text-white rounded-lg text-xs font-medium transition-all"
                  >
                    <Printer className="w-3.5 h-3.5" />
                    <span>Print Report</span>
                  </button>
                </div>
              </div>

              {/* Navigation Tabs */}
              <div className="flex items-center gap-2 border-b border-[#1E3A5F] pb-3 overflow-x-auto">
                <button
                  onClick={() => setActiveTab('overview')}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all ${
                    activeTab === 'overview'
                      ? 'bg-[#00C2FF] text-[#060D1A] shadow-md shadow-[#00C2FF]/20'
                      : 'text-[#8BA3BC] hover:text-white hover:bg-[#0D1F38]'
                  }`}
                >
                  <Shield className="w-4 h-4" />
                  <span>Overview</span>
                </button>

                <button
                  onClick={() => setActiveTab('threats')}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all ${
                    activeTab === 'threats'
                      ? 'bg-[#00C2FF] text-[#060D1A] shadow-md shadow-[#00C2FF]/20'
                      : 'text-[#8BA3BC] hover:text-white hover:bg-[#0D1F38]'
                  }`}
                >
                  <Crosshair className="w-4 h-4" />
                  <span>Threats ({result.totalFindings})</span>
                </button>

                <button
                  onClick={() => setActiveTab('mitre')}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all ${
                    activeTab === 'mitre'
                      ? 'bg-[#00C2FF] text-[#060D1A] shadow-md shadow-[#00C2FF]/20'
                      : 'text-[#8BA3BC] hover:text-white hover:bg-[#0D1F38]'
                  }`}
                >
                  <Layers className="w-4 h-4" />
                  <span>MITRE ATT&CK ({result.mitreTechniques?.length || 0})</span>
                </button>

                <button
                  onClick={() => setActiveTab('urls')}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all ${
                    activeTab === 'urls'
                      ? 'bg-[#00C2FF] text-[#060D1A] shadow-md shadow-[#00C2FF]/20'
                      : 'text-[#8BA3BC] hover:text-white hover:bg-[#0D1F38]'
                  }`}
                >
                  <Globe className="w-4 h-4" />
                  <span>Extracted URLs ({result.extractedUrls?.length || 0})</span>
                </button>

                <button
                  onClick={() => setActiveTab('logs')}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all ${
                    activeTab === 'logs'
                      ? 'bg-[#00C2FF] text-[#060D1A] shadow-md shadow-[#00C2FF]/20'
                      : 'text-[#8BA3BC] hover:text-white hover:bg-[#0D1F38]'
                  }`}
                >
                  <Terminal className="w-4 h-4" />
                  <span>Forensic Logs</span>
                </button>
              </div>

              {/* TAB 1: OVERVIEW */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  {/* Gauge Card */}
                  <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8 shadow-xl">
                    <div className="flex flex-col md:flex-row items-center justify-between gap-8">
                      {/* Left: Score Circle */}
                      <div className="flex flex-col items-center justify-center">
                        <div
                          className="relative w-36 h-36 rounded-full flex items-center justify-center border-8 shadow-2xl transition-all"
                          style={{
                            borderColor: getVerdictColor(result.verdict),
                            boxShadow: `0 0 35px ${getVerdictColor(result.verdict)}33`,
                          }}
                        >
                          <div className="text-center">
                            <span className="text-5xl font-black text-white">{result.riskScore}</span>
                            <span className="text-xs text-[#8BA3BC] block font-mono">/ 100</span>
                          </div>
                        </div>

                        <div className="mt-4 text-center">
                          <span
                            className="text-lg font-black tracking-wider uppercase px-4 py-1 rounded-full border inline-block"
                            style={{
                              color: getVerdictColor(result.verdict),
                              borderColor: `${getVerdictColor(result.verdict)}55`,
                              backgroundColor: `${getVerdictColor(result.verdict)}15`,
                            }}
                          >
                            {result.riskScore <= 39 ? 'SAFE' : result.riskScore <= 69 ? 'SUSPICIOUS' : 'MALICIOUS PHISHING'}
                          </span>
                        </div>
                      </div>

                      {/* Right: Key File Telemetry */}
                      <div className="flex-1 w-full grid grid-cols-2 gap-4">
                        <div className="bg-[#060D1A] border border-[#1E3A5F] rounded-xl p-4">
                          <p className="text-[#8BA3BC] text-xs font-semibold uppercase mb-1">File Name</p>
                          <p className="text-white text-sm font-medium truncate" title={result.fileName}>{result.fileName}</p>
                        </div>
                        <div className="bg-[#060D1A] border border-[#1E3A5F] rounded-xl p-4">
                          <p className="text-[#8BA3BC] text-xs font-semibold uppercase mb-1">File Size</p>
                          <p className="text-white text-sm font-medium">{result.fileSize}</p>
                        </div>
                        <div className="bg-[#060D1A] border border-[#1E3A5F] rounded-xl p-4">
                          <p className="text-[#8BA3BC] text-xs font-semibold uppercase mb-1">Threat Count</p>
                          <p className="text-white text-sm font-medium">{result.totalFindings} indicators</p>
                        </div>
                        <div className="bg-[#060D1A] border border-[#1E3A5F] rounded-xl p-4">
                          <p className="text-[#8BA3BC] text-xs font-semibold uppercase mb-1">Engine Duration</p>
                          <p className="text-white text-sm font-medium">{result.scanTime.toFixed(3)}s</p>
                        </div>
                      </div>
                    </div>

                    {/* SHA256 Hash Bar */}
                    <div className="mt-6 pt-6 border-t border-[#1E3A5F]">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-semibold uppercase text-[#8BA3BC]">SHA-256 Checksum</span>
                        <button
                          onClick={() => copyToClipboard(result.fileHash, 'hash')}
                          className="flex items-center gap-1 text-xs text-[#00C2FF] hover:underline"
                        >
                          {copiedHash ? <Check className="w-3.5 h-3.5 text-[#00D68F]" /> : <Copy className="w-3.5 h-3.5" />}
                          <span>{copiedHash ? 'Copied' : 'Copy Hash'}</span>
                        </button>
                      </div>
                      <p className="text-xs text-white font-mono bg-[#060D1A] border border-[#1E3A5F] p-3 rounded-xl break-all select-all">
                        {result.fileHash}
                      </p>
                    </div>
                  </div>

                  {/* Summary Highlights */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-5">
                      <div className="flex items-center gap-3 mb-2">
                        <Layers className="w-5 h-5 text-[#00C2FF]" />
                        <h4 className="text-white font-semibold text-sm">MITRE Techniques</h4>
                      </div>
                      <p className="text-2xl font-bold text-white">{result.mitreTechniques?.length || 0}</p>
                      <p className="text-xs text-[#8BA3BC] mt-1">Identified adversary attack tactics</p>
                    </div>

                    <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-5">
                      <div className="flex items-center gap-3 mb-2">
                        <Globe className="w-5 h-5 text-[#00C2FF]" />
                        <h4 className="text-white font-semibold text-sm">Extracted URLs</h4>
                      </div>
                      <p className="text-2xl font-bold text-white">{result.extractedUrls?.length || 0}</p>
                      <p className="text-xs text-[#8BA3BC] mt-1">Embedded outbound endpoints</p>
                    </div>

                    <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-5">
                      <div className="flex items-center gap-3 mb-2">
                        <Terminal className="w-5 h-5 text-[#00C2FF]" />
                        <h4 className="text-white font-semibold text-sm">Parser Telemetry</h4>
                      </div>
                      <p className="text-2xl font-bold text-white">{result.details.length}</p>
                      <p className="text-xs text-[#8BA3BC] mt-1">Security logs recorded</p>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: THREATS BREAKDOWN */}
              {activeTab === 'threats' && (
                <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-6 md:p-8 space-y-4 shadow-xl">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-bold text-white">Detected Threat Indicators ({result.totalFindings})</h3>
                    <span className="text-xs text-[#8BA3BC]">Ranked by threat weight score</span>
                  </div>

                  {result.findingsDetailed && result.findingsDetailed.length > 0 ? (
                    <div className="space-y-3">
                      {result.findingsDetailed.map((item, idx) => (
                        <div
                          key={idx}
                          className="bg-[#060D1A] border border-[#1E3A5F] rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                        >
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-white font-semibold text-sm">{item.name}</span>
                              <span
                                className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getSeverityBadgeClass(
                                  item.severity
                                )}`}
                              >
                                {item.severity}
                              </span>
                            </div>
                            <p className="text-xs text-[#8BA3BC] font-mono">ID: {item.findingType}</p>
                          </div>

                          <div className="flex items-center gap-3 self-end sm:self-center">
                            {item.mitre && (
                              <span className="text-[11px] font-mono text-[#00C2FF] bg-[#00C2FF]/10 border border-[#00C2FF]/30 px-2.5 py-1 rounded-lg">
                                {item.mitre.id}
                              </span>
                            )}
                            <span className="text-xs font-bold text-white bg-[#1E3A5F] px-3 py-1 rounded-lg">
                              +{item.score} pts
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-12 bg-[#060D1A] rounded-xl border border-[#1E3A5F]">
                      <CheckCircle className="w-12 h-12 text-[#00D68F] mx-auto mb-3" />
                      <h4 className="text-white font-bold text-base">No Malicious Indicators Found</h4>
                      <p className="text-xs text-[#8BA3BC] mt-1">This document passed all 17 static heuristic layers.</p>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 3: MITRE ATT&CK MATRIX */}
              {activeTab === 'mitre' && (
                <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-6 md:p-8 space-y-6 shadow-xl">
                  <div>
                    <h3 className="text-lg font-bold text-white mb-1">MITRE ATT&CK® Threat Mapping</h3>
                    <p className="text-xs text-[#8BA3BC]">Adversary tactics and techniques identified within this file.</p>
                  </div>

                  {result.mitreTechniques && result.mitreTechniques.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {result.mitreTechniques.map((tech, idx) => (
                        <div
                          key={idx}
                          className="bg-[#060D1A] border border-[#1E3A5F] rounded-xl p-5 hover:border-[#00C2FF]/50 transition-all"
                        >
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-xs font-bold font-mono text-[#00C2FF] bg-[#00C2FF]/10 border border-[#00C2FF]/30 px-2.5 py-1 rounded-lg">
                              {tech.id}
                            </span>
                            <span className="text-[11px] font-semibold text-[#8BA3BC] uppercase bg-[#1E3A5F]/60 px-2 py-0.5 rounded">
                              {tech.tactic}
                            </span>
                          </div>
                          <h4 className="text-white font-bold text-sm mb-1">{tech.name}</h4>
                          <p className="text-xs text-[#8BA3BC] leading-relaxed">{tech.description}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-12 bg-[#060D1A] rounded-xl border border-[#1E3A5F]">
                      <Shield className="w-12 h-12 text-[#00D68F] mx-auto mb-3" />
                      <h4 className="text-white font-bold text-base">No MITRE ATT&CK Techniques Triggered</h4>
                      <p className="text-xs text-[#8BA3BC] mt-1">No execution hooks, obfuscation, or dropper chains detected.</p>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 4: EXTRACTED URLS */}
              {activeTab === 'urls' && (
                <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-6 md:p-8 space-y-4 shadow-xl">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <h3 className="text-lg font-bold text-white">Extracted Outbound URLs ({result.extractedUrls?.length || 0})</h3>
                      <p className="text-xs text-[#8BA3BC]">Hyperlinks, QR code destinations, and formula links.</p>
                    </div>
                  </div>

                  {result.extractedUrls && result.extractedUrls.length > 0 ? (
                    <div className="space-y-3">
                      {result.extractedUrls.map((u, idx) => (
                        <div
                          key={idx}
                          className="bg-[#060D1A] border border-[#1E3A5F] rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4"
                        >
                          <div className="space-y-1 max-w-xl">
                            <div className="flex items-center gap-2">
                              <span
                                className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${
                                  u.is_suspicious
                                    ? 'bg-[#FF3B3B]/15 text-[#FF3B3B] border-[#FF3B3B]/30'
                                    : 'bg-[#00D68F]/15 text-[#00D68F] border-[#00D68F]/30'
                                }`}
                              >
                                {u.is_suspicious ? 'Suspicious' : 'Clean'}
                              </span>
                              <span className="text-xs text-[#8BA3BC] font-mono">{u.domain}</span>
                            </div>
                            <p className="text-xs text-white font-mono break-all">{u.url}</p>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {u.reasons.map((r, rIdx) => (
                                <span key={rIdx} className="text-[10px] text-[#8BA3BC] bg-[#1E3A5F]/40 px-2 py-0.5 rounded">
                                  {r}
                                </span>
                              ))}
                            </div>
                          </div>

                          <button
                            onClick={() => handleDeepScanUrl(u.url)}
                            className="flex items-center gap-1.5 px-3.5 py-2 bg-[#00C2FF]/10 hover:bg-[#00C2FF] text-[#00C2FF] hover:text-[#060D1A] border border-[#00C2FF]/40 rounded-xl text-xs font-semibold transition-all self-start md:self-center whitespace-nowrap"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                            <span>Deep Scan URL</span>
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-12 bg-[#060D1A] rounded-xl border border-[#1E3A5F]">
                      <Globe className="w-12 h-12 text-[#8BA3BC] mx-auto mb-3" />
                      <h4 className="text-white font-bold text-base">No External URLs Found</h4>
                      <p className="text-xs text-[#8BA3BC] mt-1">No hyperlinks or outbound data transfer links found.</p>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 5: FORENSIC LOGS */}
              {activeTab === 'logs' && (
                <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-6 md:p-8 space-y-4 shadow-xl">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-2">
                    <div>
                      <h3 className="text-lg font-bold text-white">Chronological Forensic Log</h3>
                      <p className="text-xs text-[#8BA3BC]">Raw heuristic engine trace output.</p>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className="relative">
                        <Search className="w-3.5 h-3.5 text-[#8BA3BC] absolute left-3 top-1/2 -translate-y-1/2" />
                        <input
                          type="text"
                          placeholder="Filter logs..."
                          value={logFilter}
                          onChange={(e) => setLogFilter(e.target.value)}
                          className="bg-[#060D1A] border border-[#1E3A5F] rounded-xl pl-8 pr-3 py-1.5 text-xs text-white placeholder-[#8BA3BC] focus:outline-none focus:border-[#00C2FF]"
                        />
                      </div>

                      <button
                        onClick={() => copyToClipboard(result.details.join('\n'), 'logs')}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-[#060D1A] border border-[#1E3A5F] hover:border-[#00C2FF] text-[#8BA3BC] hover:text-white rounded-xl text-xs font-medium transition-all"
                      >
                        {copiedLogs ? <Check className="w-3.5 h-3.5 text-[#00D68F]" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedLogs ? 'Copied' : 'Copy All'}</span>
                      </button>
                    </div>
                  </div>

                  <div className="bg-[#060D1A] border border-[#1E3A5F] rounded-xl p-4 max-h-[500px] overflow-y-auto font-mono text-xs text-slate-300 space-y-1">
                    {filteredLogs.length > 0 ? (
                      filteredLogs.map((line, idx) => (
                        <p
                          key={idx}
                          className={`${
                            line.includes('🚨') || line.includes('CRITICAL')
                              ? 'text-[#FF3B3B] font-semibold'
                              : line.includes('⚠️') || line.includes('WARNING')
                              ? 'text-[#FFAA00]'
                              : line.includes('🎯') || line.includes('🔓')
                              ? 'text-[#00C2FF]'
                              : line.includes('✅')
                              ? 'text-[#00D68F]'
                              : 'text-[#8BA3BC]'
                          }`}
                        >
                          {line}
                        </p>
                      ))
                    ) : (
                      <p className="text-[#8BA3BC] italic">No log entries matching filter.</p>
                    )}
                  </div>
                </div>
              )}
            </motion.div>
          )}
        </div>
      </main>
    </div>
  );
}