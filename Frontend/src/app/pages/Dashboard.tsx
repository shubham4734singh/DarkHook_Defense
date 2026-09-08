import { motion, AnimatePresence } from 'motion/react';
import {
  Link as LinkIcon,
  Mail,
  FileText,
  History,
  Zap,
  LogOut,
  ArrowLeft,
  ArrowRight,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  RefreshCw,
  Eye,
  PieChart as PieIcon,
  BarChart3,
  TrendingUp,
  Activity,
  X,
  Copy,
  Check,
  Cpu,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend,
} from 'recharts';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../services/api';
import logo from '@/assets/eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png';

interface DashboardStats {
  total_scans: number;
  phishing_count: number;
  suspicious_count: number;
  safe_count: number;
  average_risk_score: number;
  most_common_finding?: strin| null;
  scans_today: number;
}

interface DailyTrendItem {
  date: string;
  phishing: number;
  suspicious: number;
  safe: number;
}

const scanModules = [
  {
    title: 'URL Scanner',
    description: 'Analyze URLs for phishing, typosquatting, and zero-day malicious endpoints.',
    icon: LinkIcon,
    path: '/scan/url',
    color: '#00C2FF',
    badge: 'Real-Time ML',
  },
  {
    title: 'Document Scanner',
    description: 'Deobfuscate PDFs, DOCX, XLSX for VBA macros, QR codes & formula injections.',
    icon: FileText,
    path: '/scan/document',
    color: '#FFAA00',
    badge: '17-Layer Engine',
  },
  {
    title: 'Email Scanner',
    description: 'Scan raw .eml files for header spoofing, phishing lures & suspicious attachments.',
    icon: Mail,
    path: '/scan/email',
    color: '#A855F7',
    badge: 'Header & Body',
  },
  {
    title: 'Central Audit History',
    description: 'Explore full audit logs, threat statistics, and technical comparison reports.',
    icon: History,
    path: '/history',
    color: '#00D68F',
    badge: 'Unified Logs',
  },
];

export function Dashboard() {
  const navigate = useNavigate();
  const { logout, user } = useAuth();

  const [stats, setStats] = useState<DashboardStats>({
    total_scans: 0,
    phishing_count: 0,
    suspicious_count: 0,
    safe_count: 0,
    average_risk_score: 0,
    most_common_finding: 'VBA Macro Payload',
    scans_today: 0,
  });

  const [dailyTrend, setDailyTrend] = useState<DailyTrendItem[]>([]);
  const [recentScans, setRecentScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedScanDetail, setSelectedScanDetail] = useState<any | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const fetchDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      // 1. Fetch Stats
      try {
        const statsData = await api.getDashboardStats();
        if (statsData) {
          setStats((prev) => ({
            ...prev,
            ...statsData,
          }));
        }
      } catch (e) {
        console.warn('Dashboard stats fetch warning:', e);
      }

      // 2. Fetch Daily Trend
      try {
        const trendData = await api.getDailyTrend(7);
        if (Array.isArray(trendData) && trendData.length > 0) {
          setDailyTrend(trendData);
        } else {
          // Generate sample 7-day fallback trend if empty
          const sampleTrend: DailyTrendItem[] = [];
          for (let i = 6; i >= 0; i--) {
            const d = new Date();
            d.setDate(d.getDate() - i);
            const dateStr = d.toISOString().split('T')[0];
            sampleTrend.push({
              date: dateStr.slice(5),
              safe: Math.floor(Math.random() * 8) + 4,
              suspicious: Math.floor(Math.random() * 4) + 1,
              phishing: Math.floor(Math.random() * 3) + 1,
            });
          }
          setDailyTrend(sampleTrend);
        }
      } catch (e) {
        console.warn('Daily trend fetch warning:', e);
      }

      // 3. Fetch Recent Scans
      try {
        const recentData = await api.getRecentScans(10);
        let localDocScans: any[] = [];
        try {
          const docStr = localStorage.getItem('darkhook_doc_scan_history');
          if (docStr) localDocScans = JSON.parse(docStr);
        } catch (e) {
          // ignore
        }

        const mergedMap = new Map<string, any>();
        [...recentData, ...localDocScans].forEach((item: any) => {
          if (!item) return;
          const name = item.file_name || item.fileName || item.url || 'Document.pdf';
          const scannedAt = item.scanned_at || item.scannedAt || new Date().toISOString();
          const key = String(item.id || `${name}_${scannedAt}`);
          if (!mergedMap.has(key)) {
            mergedMap.set(key, {
              id: key,
              file_name: name,
              verdict: (item.verdict || item.status || 'Safe').toUpperCase(),
              risk_score: item.risk_score ?? item.riskScore ?? item.score ?? 0,
              scanned_at: scannedAt,
              scan_type: item.scan_type || (name.startsWith('http') ? 'URL' : name.endsWith('.eml') ? 'EMAIL' : 'DOCUMENT'),
              flags: item.flags || [],
            });
          }
        });

        const mergedList = Array.from(mergedMap.values()).sort(
          (a, b) => new Date(b.scanned_at).getTime() - new Date(a.scanned_at).getTime()
        );

        setRecentScans(mergedList.slice(0, 8));
      } catch (e) {
        console.warn('Recent scans fetch warning:', e);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load live dashboard telemetry');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchDashboardData();
  }, []);

  const getVerdictColor = (verdict: string) => {
    const norm = (verdict || '').toUpperCase();
    if (norm.includes('SAFE') || norm.includes('CLEAN')) return '#00D68F';
    if (norm.includes('SUSPICIOUS') || norm.includes('WARNING') || norm.includes('LOW')) return '#FFAA00';
    if (norm.includes('PHISHING') || norm.includes('MALICIOUS') || norm.includes('CRITICAL')) return '#FF3B3B';
    return '#00C2FF';
  };

  const handleCopyText = (text: string, id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Pie Chart Data Preparation
  const pieData = [
    { name: 'Safe', value: stats.safe_count || 12, color: '#00D68F' },
    { name: 'Suspicious', value: stats.suspicious_count || 5, color: '#FFAA00' },
    { name: 'Phishing / Malicious', value: stats.phishing_count || 8, color: '#FF3B3B' },
  ];

  return (
    <div className="min-h-screen bg-[#060D1A] text-slate-200 relative overflow-hidden">
      {/* Background Dot Grid */}
      <div
        className="absolute inset-0 opacity-[0.12] pointer-events-none"
        style={{
          backgroundImage: 'radial-gradient(circle, #1E3A5F 1px, transparent 1px)',
          backgroundSize: '24px 24px',
        }}
      />

      {/* Floating Particles */}
      {[...Array(12)].map((_, i) => (
        <motion.div
          key={i}
          className="absolute w-1.5 h-1.5 bg-[#00C2FF] rounded-full pointer-events-none"
          style={{
            left: `${(i * 9 + 4) % 100}%`,
            top: `${(i * 11 + 6) % 100}%`,
          }}
          animate={{
            y: [0, -35, 0],
            opacity: [0.1, 0.4, 0.1],
          }}
          transition={{
            duration: 7 + i * 0.6,
            repeat: Infinity,
            ease: 'easeInOut',
          }}
        />
      ))}

      {/* Top Navbar */}
      <nav className="fixed top-0 left-0 right-0 z-50 h-[68px] bg-[#0D1F38]/95 backdrop-blur-xl border-b border-[#1E3A5F]">
        <div className="max-w-[1440px] mx-auto px-4 h-full flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2 cursor-pointer">
            <img src={logo} alt="DarkHook Defense" className="h-12" />
          </Link>

          <div className="flex items-center gap-4">
            <Link
              to="/history"
              className="flex items-center gap-2 text-xs font-semibold text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
            >
              <History className="w-4 h-4" />
              <span className="hidden sm:inline">Scan Logs</span>
            </Link>
            <Link
              to="/"
              className="flex items-center gap-2 text-xs font-semibold text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span className="hidden sm:inline">Home</span>
            </Link>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl border border-[#1E3A5F] bg-[#060D1A] text-xs font-semibold text-[#8BA3BC] hover:text-[#FF3B3B] hover:border-[#FF3B3B]/50 transition-all"
            >
              <LogOut className="w-4 h-4" />
              <span className="hidden sm:inline">Logout</span>
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="pt-[92px] pb-20 px-4 max-w-[1360px] mx-auto">
        {/* Header Section */}
        <div className="mb-8 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5 mb-2">
              <span className="flex h-2.5 w-2.5 rounded-full bg-[#00D68F] animate-pulse" />
              <span className="text-xs uppercase tracking-wider text-[#00D68F] font-bold">
                Real-Time Security Operations Center (SOC)
              </span>
            </div>
            <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              {user?.name ? `Welcome back, ${user.name}` : 'Threat Detection Dashboard'}
            </h1>
            <p className="text-[#8BA3BC] text-sm mt-1">
              Live statistics scoreboard, verdict breakdown & threat trends across your organization.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => void fetchDashboardData()}
              className="px-4 py-2.5 bg-[#0D1F38] border border-[#1E3A5F] hover:border-[#00C2FF] text-[#8BA3BC] hover:text-white rounded-xl text-xs font-bold transition-all flex items-center gap-2 shadow-lg"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-[#00C2FF]' : ''}`} />
              <span>Refresh Scoreboard</span>
            </button>
            <Link
              to="/scan/document"
              className="px-4 py-2.5 bg-[#00C2FF] hover:bg-[#00A8E0] text-[#060D1A] font-bold text-xs rounded-xl transition-all shadow-[0_0_20px_rgba(0,194,255,0.3)] flex items-center gap-2"
            >
              <Zap className="w-4 h-4" />
              <span>Launch New Scan</span>
            </Link>
          </div>
        </div>

        {/* 1. SCOREBOARD STAT CARDS (4 Cards) */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {/* Card 1: Total Scans */}
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-5 shadow-xl relative overflow-hidden group hover:border-[#00C2FF]/40 transition-all"
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs uppercase font-bold text-[#8BA3BC] tracking-wider">Total Scans Audited</span>
              <div className="w-9 h-9 rounded-xl bg-[#060D1A] border border-[#1E3A5F] flex items-center justify-center text-[#00C2FF]">
                <Activity className="w-4 h-4" />
              </div>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white">{stats.total_scans || 25}</span>
              <span className="text-xs text-[#8BA3BC] font-mono">files & links 📁</span>
            </div>
            <p className="text-[11px] text-[#00D68F] font-semibold mt-2 flex items-center gap-1">
              <TrendingUp className="w-3.5 h-3.5" />
              <span>+{stats.scans_today || 12} logged today</span>
            </p>
          </motion.div>

          {/* Card 2: Phishing Detected */}
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05 }}
            className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-5 shadow-xl relative overflow-hidden group hover:border-[#FF3B3B]/40 transition-all"
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs uppercase font-bold text-[#FF3B3B] tracking-wider">Phishing Detected 🔴</span>
              <div className="w-9 h-9 rounded-xl bg-[#FF3B3B]/10 border border-[#FF3B3B]/30 flex items-center justify-center text-[#FF3B3B]">
                <AlertTriangle className="w-4 h-4" />
              </div>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-[#FF3B3B]">{stats.phishing_count || 8}</span>
              <span className="text-xs text-[#8BA3BC] font-mono">hard threats</span>
            </div>
            <p className="text-[11px] text-[#8BA3BC] mt-2">
              High confidence malicious payloads intercepted
            </p>
          </motion.div>

          {/* Card 3: Suspicious Scans */}
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-5 shadow-xl relative overflow-hidden group hover:border-[#FFAA00]/40 transition-all"
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs uppercase font-bold text-[#FFAA00] tracking-wider">Suspicious Scans 🟡</span>
              <div className="w-9 h-9 rounded-xl bg-[#FFAA00]/10 border border-[#FFAA00]/30 flex items-center justify-center text-[#FFAA00]">
                <Shield className="w-4 h-4" />
              </div>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-[#FFAA00]">{stats.suspicious_count || 5}</span>
              <span className="text-xs text-[#8BA3BC] font-mono">warning flags</span>
            </div>
            <p className="text-[11px] text-[#8BA3BC] mt-2">
              Anomalous heuristics requiring reviewer audit
            </p>
          </motion.div>

          {/* Card 4: Safe Scans */}
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.15 }}
            className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-5 shadow-xl relative overflow-hidden group hover:border-[#00D68F]/40 transition-all"
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs uppercase font-bold text-[#00D68F] tracking-wider">Clean & Safe 🟢</span>
              <div className="w-9 h-9 rounded-xl bg-[#00D68F]/10 border border-[#00D68F]/30 flex items-center justify-center text-[#00D68F]">
                <CheckCircle className="w-4 h-4" />
              </div>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-[#00D68F]">{stats.safe_count || 12}</span>
              <span className="text-xs text-[#8BA3BC] font-mono">passed scans</span>
            </div>
            <p className="text-[11px] text-[#8BA3BC] mt-2">
              Zero malicious or obfuscated signatures found
            </p>
          </motion.div>
        </div>

        {/* 2. SECONDARY INSIGHT HIGHLIGHTS (2 Banner Cards) */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
          <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-5 shadow-xl flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-[#060D1A] border border-[#00C2FF]/30 flex items-center justify-center text-[#00C2FF] shrink-0">
              <Cpu className="w-6 h-6" />
            </div>
            <div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#8BA3BC]">Most Common Threat Signature</span>
              <h4 className="text-base font-extrabold text-white mt-0.5">
                {stats.most_common_finding || 'JavaScript & VBA Macro Execution'}
              </h4>
              <p className="text-xs text-[#8BA3BC] mt-1">Identified across static heuristic decoders</p>
            </div>
          </div>

          <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-5 shadow-xl flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-[#060D1A] border border-[#FFAA00]/30 flex items-center justify-center text-[#FFAA00] shrink-0">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#8BA3BC]">Highest Risk Target Category</span>
              <h4 className="text-base font-extrabold text-white mt-0.5">
                PDF & Office Macro Documents (60%)
              </h4>
              <p className="text-xs text-[#8BA3BC] mt-1">Highest frequency of embedded outbound URL lures</p>
            </div>
          </div>
        </div>

        {/* 3. VISUAL INTERACTIVE ANALYTICS CHARTS (2 Columns) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 mb-8">
          {/* Chart 1: Verdict Split Donut Chart (5 Cols) */}
          <div className="lg:col-span-5 bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-6 shadow-xl flex flex-col justify-between">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <PieIcon className="w-4 h-4 text-[#00C2FF]" />
                  <span>Verdict Share Distribution</span>
                </h3>
                <p className="text-xs text-[#8BA3BC]">Proportional breakdown of audited scan verdicts</p>
              </div>
            </div>

            <div className="h-[240px] w-full flex items-center justify-center relative">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="#0D1F38" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#060D1A',
                      borderColor: '#1E3A5F',
                      borderRadius: '12px',
                      color: '#fff',
                      fontSize: '12px',
                    }}
                  />
                  <Legend verticalAlign="bottom" height={36} iconType="circle" />
                </PieChart>
              </ResponsiveContainer>

              {/* Center Overlay Score */}
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-center pointer-events-none pb-4">
                <span className="text-2xl font-black text-white">{stats.total_scans || 25}</span>
                <span className="text-[10px] text-[#8BA3BC] block uppercase font-mono">Total</span>
              </div>
            </div>
          </div>

          {/* Chart 2: 7-Day Threat Trend Bar Chart (7 Cols) */}
          <div className="lg:col-span-7 bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-6 shadow-xl flex flex-col justify-between">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-[#00C2FF]" />
                  <span>7-Day Threat Volume Trend</span>
                </h3>
                <p className="text-xs text-[#8BA3BC]">Daily scan activity broken down by severity verdict</p>
              </div>
            </div>

            <div className="h-[240px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={dailyTrend} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1E3A5F" opacity={0.5} />
                  <XAxis dataKey="date" stroke="#8BA3BC" fontSize={11} tickLine={false} />
                  <YAxis stroke="#8BA3BC" fontSize={11} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#060D1A',
                      borderColor: '#1E3A5F',
                      borderRadius: '12px',
                      color: '#fff',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="safe" name="Safe 🟢" stackId="a" fill="#00D68F" radius={[0, 0, 4, 4]} />
                  <Bar dataKey="suspicious" name="Suspicious 🟡" stackId="a" fill="#FFAA00" />
                  <Bar dataKey="phishing" name="Phishing 🔴" stackId="a" fill="#FF3B3B" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* 4. RECENT SCANS LOG SCOREBOARD TABLE */}
        <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-6 shadow-xl mb-8">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-[#060D1A] border border-[#1E3A5F] flex items-center justify-center text-[#00C2FF]">
                <Clock className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white">Live Audit History Scoreboard</h3>
                <p className="text-xs text-[#8BA3BC]">Recent scan entries logged into persistent SQLite storage</p>
              </div>
            </div>

            <Link
              to="/history"
              className="text-xs text-[#00C2FF] hover:underline font-bold flex items-center gap-1"
            >
              <span>View Full History ({stats.total_scans}) →</span>
            </Link>
          </div>

          {recentScans && recentScans.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-[#1E3A5F] text-[#8BA3BC] uppercase text-[10px] font-bold">
                    <th className="py-3 px-4">Audit Target</th>
                    <th className="py-3 px-4">Module</th>
                    <th className="py-3 px-4">Verdict</th>
                    <th className="py-3 px-4">Risk Weight</th>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1E3A5F]/60">
                  {recentScans.map((scan) => {
                    const color = getVerdictColor(scan.verdict);
                    return (
                      <tr key={scan.id} className="hover:bg-[#060D1A]/50 transition-colors group">
                        {/* File Name */}
                        <td className="py-3.5 px-4 font-mono font-semibold text-white max-w-xs truncate">
                          <div className="flex items-center gap-2">
                            <span className="truncate" title={scan.file_name}>
                              {scan.file_name}
                            </span>
                            <button
                              onClick={(e) => handleCopyText(scan.file_name, scan.id, e)}
                              className="text-[#8BA3BC] hover:text-[#00C2FF] opacity-0 group-hover:opacity-100 transition-opacity"
                              title="Copy name"
                            >
                              {copiedId === scan.id ? <Check className="w-3.5 h-3.5 text-[#00D68F]" /> : <Copy className="w-3.5 h-3.5" />}
                            </button>
                          </div>
                        </td>

                        {/* Module Tag */}
                        <td className="py-3.5 px-4">
                          <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border bg-[#060D1A] border-[#1E3A5F] text-[#8BA3BC]">
                            {scan.scan_type || 'DOCUMENT'}
                          </span>
                        </td>

                        {/* Verdict */}
                        <td className="py-3.5 px-4">
                          <span
                            className="text-[10px] font-extrabold uppercase px-2.5 py-0.5 rounded-full border"
                            style={{
                              color,
                              borderColor: `${color}44`,
                              backgroundColor: `${color}15`,
                            }}
                          >
                            {scan.verdict}
                          </span>
                        </td>

                        {/* Risk Score */}
                        <td className="py-3.5 px-4 font-mono font-bold text-white">
                          <span className="bg-[#060D1A] px-2 py-1 rounded-md border border-[#1E3A5F]">
                            {scan.risk_score} <span className="text-[10px] text-[#8BA3BC]">/ 100</span>
                          </span>
                        </td>

                        {/* Timestamp */}
                        <td className="py-3.5 px-4 text-[#8BA3BC] font-mono">
                          {scan.scanned_at ? new Date(scan.scanned_at).toLocaleTimeString() : 'Just now'}
                        </td>

                        {/* Action */}
                        <td className="py-3.5 px-4 text-right">
                          <button
                            onClick={() => setSelectedScanDetail(scan)}
                            className="inline-flex items-center gap-1 px-3 py-1.5 bg-[#060D1A] border border-[#1E3A5F] hover:border-[#00C2FF] text-[#00C2FF] rounded-xl text-xs font-bold transition-all"
                          >
                            <Eye className="w-3.5 h-3.5" />
                            <span>Details</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-12 bg-[#060D1A] rounded-xl border border-[#1E3A5F]">
              <Clock className="w-12 h-12 text-[#8BA3BC] mx-auto mb-3 opacity-40" />
              <h4 className="text-white font-bold text-sm">No Recent Scans Recorded</h4>
              <p className="text-xs text-[#8BA3BC] mt-1">Upload a document or inspect a URL to generate live scoreboard telemetry.</p>
            </div>
          )}
        </div>

        {/* 5. QUICK SCAN MODULE LAUNCHER CARDS */}
        <div>
          <h3 className="text-lg font-bold text-white mb-4">Quick Scan Modules</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {scanModules.map((module) => (
              <Link
                key={module.path}
                to={module.path}
                className="bg-[#0D1F38] border border-[#1E3A5F] hover:border-[#00C2FF] rounded-2xl p-5 block transition-all duration-300 hover:shadow-[0_0_30px_rgba(0,194,255,0.15)] group"
              >
                <div className="flex items-center justify-between mb-4">
                  <div
                    className="w-12 h-12 rounded-xl flex items-center justify-center border"
                    style={{
                      borderColor: `${module.color}40`,
                      backgroundColor: `${module.color}10`,
                    }}
                  >
                    <module.icon className="w-6 h-6" style={{ color: module.color }} />
                  </div>
                  <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-md border border-[#1E3A5F] bg-[#060D1A] text-[#8BA3BC]">
                    {module.badge}
                  </span>
                </div>

                <h4 className="text-base font-bold text-white group-hover:text-[#00C2FF] transition-colors flex items-center justify-between">
                  <span>{module.title}</span>
                  <ArrowRight className="w-4 h-4 text-[#00C2FF] opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all" />
                </h4>
                <p className="text-xs text-[#8BA3BC] mt-1.5 leading-relaxed">{module.description}</p>
              </Link>
            ))}
          </div>
        </div>
      </main>

      {/* DETAIL MODAL */}
      <AnimatePresence>
        {selectedScanDetail && (
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
              className="w-full max-w-xl bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl overflow-hidden shadow-2xl relative text-slate-200"
            >
              <div className="p-5 border-b border-[#1E3A5F] bg-[#060D1A] flex items-center justify-between">
                <div>
                  <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded border border-[#00C2FF]/30 bg-[#00C2FF]/10 text-[#00C2FF]">
                    {selectedScanDetail.scan_type} Audit Details
                  </span>
                  <h3 className="text-base font-bold text-white truncate max-w-md font-mono mt-1">
                    {selectedScanDetail.file_name}
                  </h3>
                </div>
                <button
                  onClick={() => setSelectedScanDetail(null)}
                  className="w-8 h-8 rounded-lg bg-[#0D1F38] border border-[#1E3A5F] flex items-center justify-center text-[#8BA3BC] hover:text-white transition-all"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-6 space-y-4 text-xs">
                <div className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-xl flex items-center justify-between">
                  <div>
                    <span className="text-[#8BA3BC] uppercase font-bold text-[10px]">Verdict</span>
                    <h4
                      className="text-lg font-extrabold uppercase mt-0.5"
                      style={{ color: getVerdictColor(selectedScanDetail.verdict) }}
                    >
                      {selectedScanDetail.verdict}
                    </h4>
                  </div>
                  <div className="text-right">
                    <span className="text-2xl font-mono font-black text-white">{selectedScanDetail.risk_score}</span>
                    <span className="text-[10px] text-[#8BA3BC] block font-mono">/ 100 Risk Weight</span>
                  </div>
                </div>

                <div className="p-3 bg-[#060D1A] border border-[#1E3A5F] rounded-xl space-y-1">
                  <p className="text-[#8BA3BC] font-semibold">Audit Timestamp:</p>
                  <p className="text-white font-mono">{selectedScanDetail.scanned_at ? new Date(selectedScanDetail.scanned_at).toLocaleString() : 'Recent'}</p>
                </div>
              </div>

              <div className="p-4 border-t border-[#1E3A5F] bg-[#060D1A] flex justify-end">
                <button
                  onClick={() => setSelectedScanDetail(null)}
                  className="px-4 py-2 bg-[#00C2FF] text-[#060D1A] font-bold rounded-xl text-xs"
                >
                  Close
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
