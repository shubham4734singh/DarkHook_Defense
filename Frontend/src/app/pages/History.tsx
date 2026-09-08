import { motion, AnimatePresence } from 'motion/react';
import {
  Shield,
  Link as LinkIcon,
  FileText,
  Mail,
  AlertTriangle,
  CheckCircle,
  Clock,
  ArrowLeft,
  RefreshCw,
  Eye,
  Scale,
  X,
  Copy,
  Check,
  Search,
  Filter,
  ExternalLink,
  Layers,
  Activity,
  Terminal,
  LogOut,
  Sparkles,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../services/api';
import logo from '@/assets/eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png';

export interface MergedScanItem {
  id: string;
  file_name: string;
  url?: string;
  scan_type: 'URL' | 'DOCUMENT' | 'EMAIL' | string;
  verdict: string;
  status?: string;
  risk_score: number;
  score?: number;
  scanned_at: string;
  file_hash?: string;
  threat_count?: number;
  flags?: string[];
  explanation?: string;
  feature_summary?: Record<string, string | number | boolean>;
  analysis_details?: any;
  screenshot?: any;
}

export function History() {
  const [scans, setScans] = useState<MergedScanItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rescanningTarget, setRescanningTarget] = useState<string | null>(null);
  const [selectedForComparison, setSelectedForComparison] = useState<MergedScanItem[]>([]);
  const [isCompareOpen, setIsCompareOpen] = useState(false);
  const [detailModalItem, setDetailModalItem] = useState<MergedScanItem | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Search and Filter States
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<'ALL' | 'URL' | 'DOCUMENT' | 'EMAIL'>('ALL');
  const [verdictFilter, setVerdictFilter] = useState<'ALL' | 'SAFE' | 'SUSPICIOUS' | 'PHISHING'>('ALL');

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

      // Fetch from API with fallback mechanisms
      const data = await api.getScanHistory();

      // Also merge with local storage items if any exist locally
      let localDocScans: any[] = [];
      try {
        const docStr = localStorage.getItem('darkhook_doc_scan_history');
        if (docStr) localDocScans = JSON.parse(docStr);
      } catch (e) {
        console.warn('Local doc parse warning:', e);
      }

      const mergedMap = new Map<string, MergedScanItem>();

      [...data, ...localDocScans].forEach((raw: any) => {
        if (!raw) return;
        const targetName = raw.file_name || raw.fileName || raw.url || 'Unidentified Audit Target';
        const rawType = (raw.scan_type || raw.scanType || '').toUpperCase();

        let scanType: 'URL' | 'DOCUMENT' | 'EMAIL' = 'DOCUMENT';
        if (rawType === 'URL' || targetName.startsWith('http://') || targetName.startsWith('https://') || targetName.startsWith('www.')) {
          scanType = 'URL';
        } else if (rawType === 'EMAIL' || targetName.endsWith('.eml')) {
          scanType = 'EMAIL';
        }

        const verdict = (raw.verdict || raw.status || 'Safe').toUpperCase();
        const score = raw.risk_score ?? raw.riskScore ?? raw.score ?? 0;
        const scannedAt = raw.scanned_at || raw.scannedAt || new Date().toISOString();
        const id = String(raw.id || `${targetName}_${scannedAt}`);

        const item: MergedScanItem = {
          id,
          file_name: targetName,
          url: targetName,
          scan_type: scanType,
          verdict,
          status: verdict,
          risk_score: score,
          score,
          scanned_at: scannedAt,
          file_hash: raw.file_hash || raw.fileHash || '',
          threat_count: raw.threat_count ?? (raw.flags?.length || 0),
          flags: raw.flags || [],
          explanation: raw.explanation || `Security audit score: ${score}/100`,
          feature_summary: raw.feature_summary,
          analysis_details: raw.analysis_details,
          screenshot: raw.screenshot,
        };

        if (!mergedMap.has(id)) {
          mergedMap.set(id, item);
        }
      });

      const mergedList = Array.from(mergedMap.values()).sort(
        (a, b) => new Date(b.scanned_at).getTime() - new Date(a.scanned_at).getTime()
      );

      setScans(mergedList);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch unified scan history');
    } finally {
      if (showLoading) setLoading(false);
    }
  };

  useEffect(() => {
    void fetchHistory();
  }, []);

  const handleCopyTarget = (text: string, id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleRescan = async (item: MergedScanItem, e: React.MouseEvent) => {
    e.stopPropagation();
    setRescanningTarget(item.id);
    try {
      if (item.scan_type === 'URL') {
        await api.scanUrl(item.file_name);
      } else if (item.scan_type === 'DOCUMENT') {
        navigate('/scan/document');
        return;
      } else {
        navigate('/scan/email');
        return;
      }
      await fetchHistory(false);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Rescan trigger failed');
    } finally {
      setRescanningTarget(null);
    }
  };

  const handleSelectCompare = (scan: MergedScanItem, e: React.MouseEvent) => {
    e.stopPropagation();
    if (scan.scan_type !== 'URL') {
      alert('Side-by-side technical comparison is specifically available for URL audit targets.');
      return;
    }

    if (selectedForComparison.some((s) => s.id === scan.id)) {
      setSelectedForComparison(selectedForComparison.filter((s) => s.id !== scan.id));
    } else {
      if (selectedForComparison.length >= 2) {
        setSelectedForComparison([selectedForComparison[0], scan]);
      } else {
        setSelectedForComparison([...selectedForComparison, scan]);
      }
    }
  };

  const getVerdictColor = (verdict: string) => {
    const norm = (verdict || '').toUpperCase();
    if (norm.includes('SAFE') || norm.includes('CLEAN')) return '#00D68F';
    if (norm.includes('SUSPICIOUS') || norm.includes('WARNING') || norm.includes('LOW')) return '#FFAA00';
    if (norm.includes('PHISHING') || norm.includes('MALICIOUS') || norm.includes('CRITICAL')) return '#FF3B3B';
    return '#00C2FF';
  };

  const getTypeIcon = (type: string) => {
    switch (type.toUpperCase()) {
      case 'URL':
        return <LinkIcon className="w-4 h-4 text-[#00C2FF]" />;
      case 'DOCUMENT':
        return <FileText className="w-4 h-4 text-[#FFAA00]" />;
      case 'EMAIL':
        return <Mail className="w-4 h-4 text-[#A855F7]" />;
      default:
        return <Shield className="w-4 h-4 text-[#00D68F]" />;
    }
  };

  const getTypeBadgeClass = (type: string) => {
    switch (type.toUpperCase()) {
      case 'URL':
        return 'bg-[#00C2FF]/10 text-[#00C2FF] border-[#00C2FF]/30';
      case 'DOCUMENT':
        return 'bg-[#FFAA00]/10 text-[#FFAA00] border-[#FFAA00]/30';
      case 'EMAIL':
        return 'bg-[#A855F7]/10 text-[#A855F7] border-[#A855F7]/30';
      default:
        return 'bg-[#00D68F]/10 text-[#00D68F] border-[#00D68F]/30';
    }
  };

  // Filtered scans calculation
  const filteredScans = scans.filter((scan) => {
    const matchesCategory = categoryFilter === 'ALL' || scan.scan_type === categoryFilter;

    let matchesVerdict = true;
    const v = scan.verdict.toUpperCase();
    if (verdictFilter === 'SAFE') {
      matchesVerdict = v.includes('SAFE') || v.includes('CLEAN');
    } else if (verdictFilter === 'SUSPICIOUS') {
      matchesVerdict = v.includes('SUSPICIOUS') || v.includes('WARNING') || v.includes('LOW');
    } else if (verdictFilter === 'PHISHING') {
      matchesVerdict = v.includes('PHISHING') || v.includes('MALICIOUS') || v.includes('CRITICAL');
    }

    const matchesSearch =
      !searchQuery ||
      scan.file_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (scan.file_hash && scan.file_hash.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (scan.flags && scan.flags.some((f) => f.toLowerCase().includes(searchQuery.toLowerCase())));

    return matchesCategory && matchesVerdict && matchesSearch;
  });

  // Calculate live summary stats
  const totalCount = scans.length;
  const safeCount = scans.filter((s) => s.verdict.includes('SAFE') || s.verdict.includes('CLEAN')).length;
  const threatCount = scans.filter(
    (s) => s.verdict.includes('PHISHING') || s.verdict.includes('MALICIOUS') || s.verdict.includes('SUSPICIOUS')
  ).length;
  const avgRiskScore = totalCount > 0 ? Math.round(scans.reduce((sum, s) => sum + s.risk_score, 0) / totalCount) : 0;

  return (
    <div className="min-h-screen bg-[#060D1A] text-white relative overflow-hidden">
      {/* Grid Pattern Background */}
      <div
        className="absolute inset-0 opacity-[0.12] pointer-events-none"
        style={{
          backgroundImage: 'radial-gradient(circle, #1E3A5F 1px, transparent 1px)',
          backgroundSize: '24px 24px',
        }}
      />

      {/* Glow Orbs */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute -top-24 -left-20 h-80 w-80 rounded-full bg-[#00C2FF]/10 blur-3xl" />
        <div className="absolute top-40 -right-24 h-96 w-96 rounded-full bg-[#A855F7]/10 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-80 w-80 rounded-full bg-[#00D68F]/10 blur-3xl" />
      </div>

      {/* Top Navbar */}
      <nav className="fixed top-0 left-0 right-0 z-50 h-[68px] bg-[#0D1F38]/95 backdrop-blur-xl border-b border-[#1E3A5F]">
        <div className="max-w-[1440px] mx-auto px-4 h-full flex items-center justify-between">
          <Link to="/dashboard" className="flex items-center gap-3 cursor-pointer">
            <img src={logo} alt="DarkHook Defense" className="h-12" />
            <div className="hidden md:block">
              <p className="text-[10px] uppercase tracking-[0.25em] text-[#8BA3BC]">DarkHook Defense</p>
              <p className="text-sm text-white font-bold">Unified Threat History Log</p>
            </div>
          </Link>

          <div className="flex items-center gap-4">
            <Link
              to="/dashboard"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl border border-[#1E3A5F] bg-[#060D1A] text-[#8BA3BC] hover:text-[#00C2FF] hover:border-[#00C2FF]/50 transition-all text-xs font-semibold"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Dashboard</span>
            </Link>
            <button
              onClick={handleLogout}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl border border-[#1E3A5F] bg-[#060D1A] text-[#8BA3BC] hover:text-[#FF3B3B] hover:border-[#FF3B3B]/50 transition-all text-xs font-semibold"
            >
              <LogOut className="w-4 h-4" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="relative z-10 max-w-6xl mx-auto px-4 pt-[96px] pb-24">
        {/* Page Header */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8"
        >
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Sparkles className="w-4 h-4 text-[#00C2FF]" />
              <span className="text-xs uppercase tracking-wider text-[#00C2FF] font-semibold">Centralized Repository</span>
            </div>
            <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
              Unified Security <span className="text-[#00C2FF]">Audit History</span>
            </h1>
            <p className="text-[#8BA3BC] text-sm mt-1">
              Live merged audit logs for URLs, Document Heuristics, and Email Header Scans.
            </p>
          </div>

          <button
            onClick={() => void fetchHistory(true)}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl border border-[#1E3A5F] bg-[#0D1F38] text-xs font-bold text-[#8BA3BC] hover:text-white hover:border-[#00C2FF] shadow-lg transition-all self-start md:self-auto"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-[#00C2FF]' : ''}`} />
            <span>Refresh Scan Log</span>
          </button>
        </motion.div>

        {/* Live Metrics Summary Bar */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8"
        >
          <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-4 shadow-xl">
            <p className="text-xs font-semibold uppercase text-[#8BA3BC] mb-1">Total Audited Scans</p>
            <p className="text-3xl font-extrabold text-white">{totalCount}</p>
            <p className="text-[11px] text-[#8BA3BC] mt-1">Persisted in SQLite database</p>
          </div>

          <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-4 shadow-xl">
            <p className="text-xs font-semibold uppercase text-[#00D68F] mb-1">Safe Verdicts</p>
            <p className="text-3xl font-extrabold text-[#00D68F]">{safeCount}</p>
            <p className="text-[11px] text-[#8BA3BC] mt-1">Passed all signature layers</p>
          </div>

          <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-4 shadow-xl">
            <p className="text-xs font-semibold uppercase text-[#FF3B3B] mb-1">Threats Detected</p>
            <p className="text-3xl font-extrabold text-[#FF3B3B]">{threatCount}</p>
            <p className="text-[11px] text-[#8BA3BC] mt-1">Suspicious or Malicious flags</p>
          </div>

          <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-4 shadow-xl">
            <p className="text-xs font-semibold uppercase text-[#00C2FF] mb-1">Average Risk Score</p>
            <p className="text-3xl font-extrabold text-[#00C2FF]">{avgRiskScore} <span className="text-xs text-[#8BA3BC]">/ 100</span></p>
            <p className="text-[11px] text-[#8BA3BC] mt-1">Across all historical entries</p>
          </div>
        </motion.div>

        {/* Selected Scans for Comparison Banner */}
        {selectedForComparison.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-6 p-4 rounded-2xl border border-[#00C2FF]/40 bg-[#00C2FF]/10 flex items-center justify-between gap-4 flex-wrap shadow-xl"
          >
            <div className="flex items-center gap-3">
              <Scale className="w-5 h-5 text-[#00C2FF]" />
              <div>
                <p className="text-white text-sm font-bold">URL Threat Comparison Console</p>
                <p className="text-xs text-[#8BA3BC]">
                  {selectedForComparison.length === 1
                    ? 'Select 1 more URL scan to compare technical metrics side-by-side'
                    : '2 URLs selected! Ready to launch side-by-side metric comparison.'}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setSelectedForComparison([])}
                className="px-3 py-1.5 rounded-xl border border-[#1E3A5F] hover:bg-[#060D1A] text-xs text-[#8BA3BC] hover:text-white transition-all font-medium"
              >
                Clear Selection
              </button>
              <button
                onClick={() => setIsCompareOpen(true)}
                disabled={selectedForComparison.length < 2}
                className="px-4 py-1.5 rounded-xl bg-[#00C2FF] text-[#060D1A] text-xs font-bold hover:bg-[#00A8E0] transition-all disabled:opacity-40 shadow-md shadow-[#00C2FF]/20"
              >
                Compare Scans
              </button>
            </div>
          </motion.div>
        )}

        {/* Filters and Controls Card */}
        <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-5 mb-6 shadow-xl space-y-4">
          {/* Row 1: Search & Verdict Filter */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            {/* Search Box */}
            <div className="relative w-full sm:flex-1">
              <Search className="w-4 h-4 text-[#8BA3BC] absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search by file name, URL, SHA-256 hash, or threat flag..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-[#060D1A] border border-[#1E3A5F] rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-[#8BA3BC] focus:outline-none focus:border-[#00C2FF] transition-all"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-[#8BA3BC] hover:text-white"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Verdict Filter Dropdown */}
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <Filter className="w-4 h-4 text-[#8BA3BC] shrink-0" />
              <span className="text-xs text-[#8BA3BC] font-semibold shrink-0">Verdict:</span>
              <select
                value={verdictFilter}
                onChange={(e) => setVerdictFilter(e.target.value as any)}
                className="w-full sm:w-auto bg-[#060D1A] border border-[#1E3A5F] text-white text-xs rounded-xl px-3 py-2.5 focus:outline-none focus:border-[#00C2FF]"
              >
                <option value="ALL">All Verdicts</option>
                <option value="SAFE">Safe / Clean</option>
                <option value="SUSPICIOUS">Suspicious</option>
                <option value="PHISHING">Phishing / Malicious</option>
              </select>
            </div>
          </div>

          {/* Row 2: Category Filter Tabs */}
          <div className="flex items-center gap-2 border-t border-[#1E3A5F] pt-4 overflow-x-auto">
            <button
              onClick={() => setCategoryFilter('ALL')}
              className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all ${
                categoryFilter === 'ALL'
                  ? 'bg-[#00C2FF] text-[#060D1A] shadow-md shadow-[#00C2FF]/20'
                  : 'text-[#8BA3BC] hover:text-white hover:bg-[#060D1A]'
              }`}
            >
              <Shield className="w-4 h-4" />
              <span>All Scans ({scans.length})</span>
            </button>

            <button
              onClick={() => setCategoryFilter('URL')}
              className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all ${
                categoryFilter === 'URL'
                  ? 'bg-[#00C2FF] text-[#060D1A] shadow-md shadow-[#00C2FF]/20'
                  : 'text-[#8BA3BC] hover:text-white hover:bg-[#060D1A]'
              }`}
            >
              <LinkIcon className="w-4 h-4" />
              <span>URL Scans ({scans.filter((s) => s.scan_type === 'URL').length})</span>
            </button>

            <button
              onClick={() => setCategoryFilter('DOCUMENT')}
              className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all ${
                categoryFilter === 'DOCUMENT'
                  ? 'bg-[#FFAA00] text-[#060D1A] shadow-md shadow-[#FFAA00]/20'
                  : 'text-[#8BA3BC] hover:text-white hover:bg-[#060D1A]'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>Document Scans ({scans.filter((s) => s.scan_type === 'DOCUMENT').length})</span>
            </button>

            <button
              onClick={() => setCategoryFilter('EMAIL')}
              className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all ${
                categoryFilter === 'EMAIL'
                  ? 'bg-[#A855F7] text-white shadow-md shadow-[#A855F7]/20'
                  : 'text-[#8BA3BC] hover:text-white hover:bg-[#060D1A]'
              }`}
            >
              <Mail className="w-4 h-4" />
              <span>Email Scans ({scans.filter((s) => s.scan_type === 'EMAIL').length})</span>
            </button>
          </div>
        </div>

        {/* Scan Log List */}
        {loading ? (
          <div className="py-24 text-center bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl">
            <RefreshCw className="w-10 h-10 text-[#00C2FF] animate-spin mx-auto mb-4" />
            <p className="text-white font-bold text-base">Loading Unified Audit Log...</p>
            <p className="text-[#8BA3BC] text-xs mt-1">Merging SQLite database & URL cache entries</p>
          </div>
        ) : error ? (
          <div className="p-8 border border-[#FF3B3B]/40 bg-[#FF3B3B]/10 rounded-2xl text-center">
            <AlertTriangle className="w-12 h-12 text-[#FF3B3B] mx-auto mb-3" />
            <p className="text-[#FF3B3B] font-bold text-base mb-1">Failed to Load Scan Logs</p>
            <p className="text-red-300 text-xs mb-4">{error}</p>
            <button
              onClick={() => void fetchHistory()}
              className="px-4 py-2 bg-[#FF3B3B]/20 border border-[#FF3B3B]/50 text-white text-xs font-bold rounded-xl hover:bg-[#FF3B3B]/30 transition-all"
            >
              Retry Loading
            </button>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="border border-[#1E3A5F] bg-[#0D1F38] rounded-2xl p-16 text-center shadow-xl">
            <Clock className="w-14 h-14 text-[#8BA3BC] mx-auto mb-4 opacity-40" />
            <h3 className="text-xl font-bold text-white mb-2">No Matching Scan Records Found</h3>
            <p className="text-[#8BA3BC] text-xs max-w-md mx-auto mb-6">
              {searchQuery || categoryFilter !== 'ALL' || verdictFilter !== 'ALL'
                ? 'No past scans match your current filter or search criteria. Try adjusting your filters above.'
                : 'Upload documents or inspect URLs using the DarkHook Defense modules to record audit history entries.'}
            </p>
            <div className="flex flex-wrap items-center justify-center gap-3">
              <Link
                to="/scan/document"
                className="px-4 py-2.5 bg-[#00C2FF] text-[#060D1A] font-bold rounded-xl text-xs shadow-md hover:bg-[#00A8E0] transition-all"
              >
                Scan a Document
              </Link>
              <Link
                to="/scan/url"
                className="px-4 py-2.5 bg-[#060D1A] border border-[#1E3A5F] hover:border-[#00C2FF] text-white font-bold rounded-xl text-xs transition-all"
              >
                Scan a URL
              </Link>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {filteredScans.map((scan, idx) => {
              const isSelected = selectedForComparison.some((s) => s.id === scan.id);
              const verdictColor = getVerdictColor(scan.verdict);

              return (
                <motion.div
                  key={scan.id || idx}
                  initial={{ opacity: 0, y: 15 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.03 }}
                  className="bg-[#0D1F38] border border-[#1E3A5F] hover:border-[#00C2FF]/50 rounded-2xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all duration-300 hover:shadow-[0_8px_30px_rgba(0,194,255,0.1)] group"
                >
                  {/* Left Column: Icon + File Details */}
                  <div className="flex items-start md:items-center gap-4 min-w-0 flex-1">
                    {/* Checkbox for comparison (URL only) */}
                    {scan.scan_type === 'URL' && (
                      <div
                        onClick={(e) => handleSelectCompare(scan, e)}
                        className="p-1 cursor-pointer shrink-0 mt-1 md:mt-0"
                        title="Select for side-by-side URL comparison"
                      >
                        <div
                          className={`w-4 h-4 rounded border flex items-center justify-center transition-all ${
                            isSelected ? 'border-[#00C2FF] bg-[#00C2FF]' : 'border-[#1E3A5F] hover:border-[#00C2FF]'
                          }`}
                        >
                          {isSelected && <Check className="w-3 h-3 text-[#060D1A] stroke-[3]" />}
                        </div>
                      </div>
                    )}

                    {/* Scan Module Badge Icon */}
                    <div className="w-12 h-12 rounded-xl bg-[#060D1A] border border-[#1E3A5F] flex items-center justify-center shrink-0">
                      {getTypeIcon(scan.scan_type)}
                    </div>

                    {/* Target Meta */}
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className={`text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-md border ${getTypeBadgeClass(scan.scan_type)}`}>
                          {scan.scan_type}
                        </span>
                        <span className="text-[#8BA3BC] text-[10px]">•</span>
                        <span className="text-[#8BA3BC] text-xs font-mono">
                          {scan.scanned_at ? new Date(scan.scanned_at).toLocaleString() : 'Recent'}
                        </span>
                        {scan.threat_count !== undefined && scan.threat_count > 0 && (
                          <span className="text-[10px] font-semibold text-[#FF3B3B] bg-[#FF3B3B]/10 border border-[#FF3B3B]/30 px-2 py-0.5 rounded-md">
                            {scan.threat_count} threat indicators
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <p className="text-white text-sm font-bold truncate max-w-md font-mono" title={scan.file_name}>
                          {scan.file_name}
                        </p>
                        <button
                          onClick={(e) => handleCopyTarget(scan.file_name, scan.id, e)}
                          className="text-[#8BA3BC] hover:text-[#00C2FF] transition-colors p-1"
                          title="Copy target name to clipboard"
                        >
                          {copiedId === scan.id ? <Check className="w-3.5 h-3.5 text-[#00D68F]" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>

                      {scan.file_hash && (
                        <p className="text-[11px] text-[#8BA3BC] font-mono truncate max-w-sm mt-0.5">
                          SHA256: {scan.file_hash.slice(0, 16)}...
                        </p>
                      )}
                    </div>
                  </div>

                  {/* Right Column: Score Gauge & Actions */}
                  <div className="flex items-center justify-between md:justify-end gap-4 shrink-0 border-t md:border-t-0 border-[#1E3A5F] pt-3 md:pt-0">
                    {/* Score Circle & Verdict Pill */}
                    <div className="flex items-center gap-3">
                      <div
                        className="w-10 h-10 rounded-full border-2 flex items-center justify-center font-bold text-xs font-mono"
                        style={{
                          borderColor: verdictColor,
                          color: verdictColor,
                          backgroundColor: `${verdictColor}15`,
                        }}
                      >
                        {scan.risk_score}
                      </div>

                      <span
                        className="text-xs font-black uppercase tracking-wider px-3 py-1 rounded-lg border select-none"
                        style={{
                          color: verdictColor,
                          borderColor: `${verdictColor}44`,
                          backgroundColor: `${verdictColor}15`,
                        }}
                      >
                        {scan.verdict}
                      </span>
                    </div>

                    {/* Action Buttons */}
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setDetailModalItem(scan)}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-[#060D1A] border border-[#1E3A5F] hover:border-[#00C2FF] text-[#00C2FF] rounded-xl text-xs font-semibold transition-all"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span className="hidden sm:inline">Inspect Details</span>
                      </button>

                      <button
                        onClick={(e) => void handleRescan(scan, e)}
                        disabled={rescanningTarget === scan.id}
                        className="p-2 bg-[#060D1A] border border-[#1E3A5F] hover:border-[#00C2FF] text-[#8BA3BC] hover:text-white rounded-xl transition-all"
                        title="Re-run scanner"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${rescanningTarget === scan.id ? 'animate-spin text-[#00C2FF]' : ''}`} />
                      </button>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        )}
      </main>

      {/* INSPECTION DETAILS MODAL */}
      <AnimatePresence>
        {detailModalItem && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-[#040810]/85 backdrop-blur-md overflow-y-auto px-4 py-8 flex items-center justify-center"
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-2xl bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl overflow-hidden shadow-2xl relative text-slate-200"
            >
              {/* Modal Header */}
              <div className="p-6 border-b border-[#1E3A5F] bg-[#060D1A] flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-[#0D1F38] border border-[#1E3A5F] flex items-center justify-center">
                    {getTypeIcon(detailModalItem.scan_type)}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${getTypeBadgeClass(detailModalItem.scan_type)}`}>
                        {detailModalItem.scan_type} AUDIT REPORT
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-white truncate max-w-md font-mono mt-0.5">
                      {detailModalItem.file_name}
                    </h3>
                  </div>
                </div>

                <button
                  onClick={() => setDetailModalItem(null)}
                  className="w-8 h-8 rounded-lg bg-[#0D1F38] border border-[#1E3A5F] flex items-center justify-center text-[#8BA3BC] hover:text-white hover:border-[#00C2FF] transition-all"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Modal Body */}
              <div className="p-6 space-y-6 max-h-[70vh] overflow-y-auto">
                {/* Score & Verdict Banner */}
                <div className="p-4 rounded-xl bg-[#060D1A] border border-[#1E3A5F] flex items-center justify-between gap-4">
                  <div>
                    <span className="text-xs uppercase text-[#8BA3BC] font-semibold">Audit Verdict</span>
                    <h4
                      className="text-xl font-extrabold tracking-wide uppercase mt-0.5"
                      style={{ color: getVerdictColor(detailModalItem.verdict) }}
                    >
                      {detailModalItem.verdict}
                    </h4>
                    <p className="text-xs text-[#8BA3BC] mt-1">{detailModalItem.explanation}</p>
                  </div>

                  <div className="text-center shrink-0">
                    <div
                      className="w-16 h-16 rounded-full border-4 flex items-center justify-center text-xl font-bold font-mono shadow-lg"
                      style={{
                        borderColor: getVerdictColor(detailModalItem.verdict),
                        color: getVerdictColor(detailModalItem.verdict),
                        backgroundColor: `${getVerdictColor(detailModalItem.verdict)}15`,
                      }}
                    >
                      {detailModalItem.risk_score}
                    </div>
                    <span className="text-[10px] text-[#8BA3BC] block mt-1 font-mono">Risk Weight</span>
                  </div>
                </div>

                {/* Audit Telemetry Meta */}
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-[#060D1A] border border-[#1E3A5F] rounded-xl">
                    <p className="text-[#8BA3BC] font-semibold uppercase mb-1">Timestamp</p>
                    <p className="text-white font-mono">{detailModalItem.scanned_at ? new Date(detailModalItem.scanned_at).toLocaleString() : 'N/A'}</p>
                  </div>
                  <div className="p-3 bg-[#060D1A] border border-[#1E3A5F] rounded-xl">
                    <p className="text-[#8BA3BC] font-semibold uppercase mb-1">Audit Entry ID</p>
                    <p className="text-white font-mono truncate">{detailModalItem.id}</p>
                  </div>
                </div>

                {/* Detected Threat Flags & Signatures */}
                <div>
                  <h5 className="text-xs font-bold uppercase text-[#00C2FF] mb-3 flex items-center gap-1.5">
                    <Terminal className="w-4 h-4" />
                    <span>Detected Heuristic Flags & Indicators ({detailModalItem.flags?.length || 0})</span>
                  </h5>

                  {detailModalItem.flags && detailModalItem.flags.length > 0 ? (
                    <div className="space-y-2 bg-[#060D1A] p-4 rounded-xl border border-[#1E3A5F]">
                      {detailModalItem.flags.map((flag, fIdx) => (
                        <div key={fIdx} className="flex items-start gap-2 text-xs font-mono">
                          <span className="text-[#FF3B3B] font-bold">•</span>
                          <span className="text-slate-200 break-all">{flag}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-xl text-center text-xs text-[#00D68F] font-semibold flex items-center justify-center gap-2">
                      <CheckCircle className="w-4 h-4 text-[#00D68F]" />
                      <span>Passed all heuristic layers with zero flagged indicators.</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Modal Footer */}
              <div className="p-4 border-t border-[#1E3A5F] bg-[#060D1A] flex items-center justify-between">
                <span className="text-xs text-[#8BA3BC]">DarkHook Defense Threat Database</span>
                <button
                  onClick={() => setDetailModalItem(null)}
                  className="px-4 py-2 bg-[#00C2FF] text-[#060D1A] font-bold rounded-xl text-xs hover:bg-[#00A8E0] transition-all"
                >
                  Close Modal
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Comparison Modal */}
      <AnimatePresence>
        {isCompareOpen && selectedForComparison.length === 2 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-[#040810]/95 backdrop-blur-md overflow-y-auto px-4 py-8"
          >
            <div className="max-w-5xl mx-auto border border-[#1E3A5F] bg-[#0D1F38] rounded-2xl overflow-hidden shadow-2xl relative">
              {/* Header */}
              <div className="p-6 border-b border-[#1E3A5F] flex items-center justify-between bg-[#060D1A]">
                <div className="flex items-center gap-3">
                  <Scale className="w-6 h-6 text-[#00C2FF]" />
                  <div>
                    <h3 className="text-xl font-bold text-white">URL Security Comparison Console</h3>
                    <p className="text-xs text-[#8BA3BC]">Side-by-side technical analysis of two audited targets.</p>
                  </div>
                </div>
                <button
                  onClick={() => setIsCompareOpen(false)}
                  className="h-10 w-10 rounded-xl bg-[#0D1F38] border border-[#1E3A5F] flex items-center justify-center text-gray-400 hover:text-white hover:border-[#00C2FF] transition-all"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Grid Content */}
              <div className="p-6 space-y-6">
                <div className="grid gap-6 md:grid-cols-2">
                  <div className="p-5 bg-[#060D1A] border border-[#1E3A5F] rounded-2xl relative overflow-hidden">
                    <p className="text-[#00C2FF] text-[10px] uppercase tracking-wider mb-2 font-bold">Audit Subject A</p>
                    <p className="text-white text-xs font-mono font-bold break-all">{selectedForComparison[0].file_name}</p>
                    <p className="text-[10px] text-[#8BA3BC] mt-2 font-mono">
                      Verdict: {selectedForComparison[0].verdict} ({selectedForComparison[0].risk_score}/100)
                    </p>
                  </div>

                  <div className="p-5 bg-[#060D1A] border border-[#1E3A5F] rounded-2xl relative overflow-hidden">
                    <p className="text-[#A855F7] text-[10px] uppercase tracking-wider mb-2 font-bold">Audit Subject B</p>
                    <p className="text-white text-xs font-mono font-bold break-all">{selectedForComparison[1].file_name}</p>
                    <p className="text-[10px] text-[#8BA3BC] mt-2 font-mono">
                      Verdict: {selectedForComparison[1].verdict} ({selectedForComparison[1].risk_score}/100)
                    </p>
                  </div>
                </div>

                {/* Score Comparison */}
                <div className="grid gap-6 md:grid-cols-2 border-t border-[#1E3A5F] pt-6">
                  <div className="p-6 bg-[#060D1A] border border-[#1E3A5F] rounded-2xl text-center flex flex-col items-center justify-center">
                    <div
                      className="w-20 h-20 rounded-full border-4 flex items-center justify-center mb-3 text-xl font-bold font-mono"
                      style={{
                        borderColor: getVerdictColor(selectedForComparison[0].verdict),
                        color: getVerdictColor(selectedForComparison[0].verdict),
                      }}
                    >
                      {selectedForComparison[0].risk_score}
                    </div>
                    <h5 className="text-base font-bold uppercase text-white">{selectedForComparison[0].verdict}</h5>
                  </div>

                  <div className="p-6 bg-[#060D1A] border border-[#1E3A5F] rounded-2xl text-center flex flex-col items-center justify-center">
                    <div
                      className="w-20 h-20 rounded-full border-4 flex items-center justify-center mb-3 text-xl font-bold font-mono"
                      style={{
                        borderColor: getVerdictColor(selectedForComparison[1].verdict),
                        color: getVerdictColor(selectedForComparison[1].verdict),
                      }}
                    >
                      {selectedForComparison[1].risk_score}
                    </div>
                    <h5 className="text-base font-bold uppercase text-white">{selectedForComparison[1].verdict}</h5>
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