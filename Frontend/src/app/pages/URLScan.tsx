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
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute -top-24 -left-20 h-72 w-72 rounded-full bg-[#00C2FF]/10 blur-3xl" />
        <div className="absolute top-40 -right-24 h-96 w-96 rounded-full bg-[#7C3AED]/10 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-80 w-80 rounded-full bg-[#10B981]/10 blur-3xl" />
      </div>

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
        <div className="max-w-7xl mx-auto space-y-8">
          <motion.section
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]"
          >
            <div className="rounded-[28px] border border-[#1A3654] bg-gradient-to-br from-[#08111E] via-[#0A1526] to-[#07111F] p-6 sm:p-8 shadow-[0_24px_80px_rgba(0,0,0,0.35)] overflow-hidden relative">
              <div className={`absolute inset-x-0 top-0 h-1 bg-gradient-to-r ${result ? scoreTone : 'from-[#00C2FF]/70 via-[#10B981]/40 to-transparent'}`} />
              <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
                <div className="flex items-center gap-4">
                  <div className="h-14 w-14 rounded-2xl bg-[#071321] border border-[#1A3654] flex items-center justify-center shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]">
                    <LinkIcon className="w-7 h-7 text-[#00C2FF]" />
                  </div>
                  <div>
                    <p className="text-[11px] uppercase tracking-[0.32em] text-[#7FA0C4] mb-1">URL Intelligence</p>
                    <h1 className="text-3xl sm:text-4xl font-black tracking-tight text-white">Scan a suspicious link</h1>
                    <p className="text-[#98B3CD] mt-2 max-w-2xl">
                      Paste a URL to inspect phishing signals, runtime behavior, and an explainable risk breakdown in one place.
                    </p>
                  </div>
                </div>
                <div className="inline-flex items-center gap-2 px-3 py-2 rounded-full border border-[#1F3E63] bg-[#08111E] text-[#9BC1DE] text-sm">
                  <Sparkles className="w-4 h-4 text-[#00C2FF]" />
                  Live backend connected
                </div>
              </div>

              <div className="grid gap-3 sm:grid-cols-3 mb-6">
                <MiniMetric label="Static Heuristics" value="31 signals" />
                <MiniMetric label="Runtime Checks" value="Forms, redirects, TLS" />
                <MiniMetric label="ML Verdict" value="Hosted inference" />
              </div>

              <div className="space-y-4">
                <label className="block text-sm font-semibold text-white">Enter URL to scan</label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-[#6D88A6]">
                    <ScanLine className="w-4 h-4" />
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

                <div className="flex flex-wrap gap-2">
                  {sampleUrls.map((sample) => (
                    <button
                      key={sample}
                      type="button"
                      onClick={() => fillSample(sample)}
                      className="px-3 py-2 rounded-full text-xs sm:text-sm border border-[#1D3555] bg-[#050A14] text-[#A7C1DB] hover:text-white hover:border-[#00C2FF]/45 hover:bg-[#00C2FF]/10 transition-all"
                    >
                      {sample}
                    </button>
                  ))}
                </div>

                <div className="grid gap-3 sm:grid-cols-3">
                  <button
                    onClick={handleScan}
                    disabled={!trimmedUrl || scanning}
                    className="inline-flex items-center justify-center gap-2 h-12 rounded-2xl bg-[#00C2FF] text-[#04101E] font-bold shadow-[0_12px_30px_rgba(0,194,255,0.28)] hover:bg-[#33CCFF] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {scanning ? (
                      <>
                        <Gauge className="w-4 h-4 animate-pulse" />
                        Scanning...
                      </>
                    ) : (
                      <>
                        <ShieldAlert className="w-4 h-4" />
                        Scan URL
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={clearForm}
                    className="inline-flex items-center justify-center gap-2 h-12 rounded-2xl border border-[#1D3555] bg-[#050A14] text-[#A7C1DB] hover:text-white hover:border-[#00C2FF]/45 hover:bg-[#00C2FF]/10 transition-all"
                  >
                    <Trash2 className="w-4 h-4" />
                    Clear
                  </button>
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(trimmedUrl || '');
                      } catch {
                        // Ignore clipboard failures; the scan flow still works.
                      }
                    }}
                    className="inline-flex items-center justify-center gap-2 h-12 rounded-2xl border border-[#1D3555] bg-[#050A14] text-[#A7C1DB] hover:text-white hover:border-[#00C2FF]/45 hover:bg-[#00C2FF]/10 transition-all"
                  >
                    <ClipboardPaste className="w-4 h-4" />
                    Copy input
                  </button>
                </div>
              </div>
            </div>

            <div className="rounded-[28px] border border-[#1A3654] bg-[#08111E]/90 p-6 sm:p-8 backdrop-blur-xl">
              <div className="flex items-center gap-3 mb-5">
                <div className="h-11 w-11 rounded-2xl bg-[#05101D] border border-[#1A3654] flex items-center justify-center">
                  <Gauge className="w-5 h-5 text-[#00C2FF]" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">Analysis cockpit</h2>
                  <p className="text-[#98B3CD] text-sm">A fast overview of the scan pipeline and risk posture.</p>
                </div>
              </div>

              <div className="space-y-3">
                <StatusRow label="Current backend" value="darkhook-defense.onrender.com" />
                <StatusRow label="Runtime engine" value="HTML + redirect + screenshot inspection" />
                <StatusRow label="Model source" value="Hosted Hugging Face inference" />
                <StatusRow label="Threat feed" value="Local + optional external intelligence" />
              </div>

              <div className="mt-6 rounded-2xl border border-[#1D3555] bg-gradient-to-br from-[#05101D] to-[#0A1526] p-5">
                <p className="text-[11px] uppercase tracking-[0.28em] text-[#7FA0C4] mb-2">What the scanner checks</p>
                <ul className="space-y-2 text-sm text-[#B3C8DC]">
                  <li className="flex items-start gap-2"><span className="text-[#00C2FF] mt-0.5">•</span> URL structure, suspicious keywords, and brand impersonation</li>
                  <li className="flex items-start gap-2"><span className="text-[#00C2FF] mt-0.5">•</span> Runtime redirects, forms, scripts, and screenshot capture</li>
                  <li className="flex items-start gap-2"><span className="text-[#00C2FF] mt-0.5">•</span> Heuristic scoring combined with model output and threat intel</li>
                </ul>
              </div>
            </div>
          </motion.section>

          {error && (
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              className="rounded-2xl border border-red-500/40 bg-red-500/10 p-4 sm:p-5"
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

          {result && (
            <motion.section
              initial={{ opacity: 0, y: 18 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-8"
            >
              <div className={`rounded-[28px] border border-[#1A3654] bg-gradient-to-br ${scoreTone} from-15% p-6 sm:p-8 relative overflow-hidden`}>
                <div className="absolute inset-0 pointer-events-none opacity-50">
                  <div className="absolute -right-12 top-0 h-36 w-36 rounded-full bg-white/5 blur-3xl" />
                </div>
                <div className="grid gap-6 lg:grid-cols-[240px_1fr] items-center relative">
                  <div className="mx-auto lg:mx-0 flex flex-col items-center">
                    <div className="relative w-44 h-44 rounded-full border-[10px] flex items-center justify-center shadow-[0_0_60px_rgba(0,194,255,0.08)]" style={{ borderColor: getStatusColor(result.status) }}>
                      <div className="absolute inset-3 rounded-full bg-[#07111F]/90 border border-white/5 flex flex-col items-center justify-center text-center">
                        <div className="flex items-center gap-2 mb-1" style={{ color: getStatusColor(result.status) }}>
                          {getStatusIcon(result.status)}
                          <span className="text-xs uppercase tracking-[0.24em] font-semibold">{result.status}</span>
                        </div>
                        <div className="text-5xl font-black text-white leading-none">{result.score}</div>
                        <p className="text-[#9BB5CE] text-xs mt-2">out of 100</p>
                      </div>
                    </div>

                    <div className="mt-4 inline-flex items-center gap-2 px-3 py-2 rounded-full border border-white/10 bg-black/20 text-sm" style={{ color: getStatusColor(result.status) }}>
                      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: getStatusColor(result.status) }} />
                      {result.status === 'safe' ? 'Low risk' : result.status === 'suspicious' ? 'Elevated risk' : 'High risk'}
                    </div>
                  </div>

                  <div className="space-y-5">
                    <div>
                      <div className="flex flex-wrap items-center gap-3 mb-3">
                        <h2 className="text-2xl sm:text-3xl font-black text-white">{result.verdict}</h2>
                        <span className="px-3 py-1 rounded-full text-xs font-semibold border border-white/10 bg-white/5 text-[#D2E5F5]">
                          {confidenceLabel}: {confidencePercent}%
                        </span>
                      </div>
                      <p className="text-[#D1E0EE] text-base leading-relaxed max-w-3xl">{result.explanation}</p>
                    </div>

                    <div className="grid gap-4 sm:grid-cols-3">
                      <MetricCard label="Confidence" value={`${confidencePercent}%`} helper={result.status === 'safe' ? 'Model agrees with the safe verdict' : 'Confidence includes static, runtime, and model signals'} />
                      <MetricCard label="Keyword hits" value={String(result.feature_summary?.keyword_hits || 0)} helper="Phishing words found in the URL" />
                      <MetricCard label="URL length" value={`${result.feature_summary?.url_length || 0} chars`} helper="Long URLs often hide malicious intent" />
                    </div>

                    <div className="rounded-2xl border border-white/10 bg-black/20 p-4 sm:p-5">
                      <div className="flex items-center justify-between gap-4 mb-3">
                        <p className="text-sm font-semibold text-white">Confidence meter</p>
                        <p className="text-xs text-[#A7C1DB]">{confidenceLabel}</p>
                      </div>
                      <div className="h-3 rounded-full bg-white/5 overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${confidencePercent}%`,
                            background: `linear-gradient(90deg, ${getStatusColor(result.status)}, rgba(255,255,255,0.7))`,
                          }}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
                <div className="space-y-6">
                  <Panel title="Scan snapshot" icon={<ScanLine className="w-4 h-4" />}>
                    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
                      <DetailCard label="Scanned URL" value={result.url} />
                      <DetailCard label="Host" value={parsedUrl?.hostname || 'n/a'} />
                      <DetailCard label="Dynamic status" value={analysisDetails?.dynamic_status || 'unavailable'} />
                      <DetailCard label="Keyword hits" value={String(result.feature_summary?.keyword_hits || 0)} />
                    </div>
                  </Panel>

                  {analysisDetails && (
                    <Panel title="Detailed assessment" icon={<Sparkles className="w-4 h-4" />}>
                      <div className="flex items-start justify-between gap-4 mb-5 flex-wrap">
                        <div>
                          <p className="text-[#D1E0EE] text-sm leading-relaxed max-w-3xl">{analysisDetails.summary}</p>
                        </div>
                        <div className="px-4 py-2 rounded-xl bg-[#06101D] border border-[#1B3557]">
                          <p className="text-[#8BA3BC] text-[11px] uppercase tracking-[0.22em] mb-1">Analysis engine</p>
                          <p className="text-white text-sm font-semibold">{analysisDetails.model_source}</p>
                        </div>
                      </div>

                      {topRisks.length > 0 && (
                        <SectionBlock title="Top risk drivers">
                          <div className="flex flex-wrap gap-2">
                            {topRisks.map((risk, index) => (
                              <Tag key={index}>{risk}</Tag>
                            ))}
                          </div>
                        </SectionBlock>
                      )}

                      {parsedUrl && (
                        <SectionBlock title="Parsed URL">
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <DetailCard label="Scheme" value={parsedUrl.scheme || 'n/a'} />
                            <DetailCard label="Hostname" value={parsedUrl.hostname || 'n/a'} />
                            <DetailCard label="Base domain" value={parsedUrl.base_domain || 'n/a'} />
                            <DetailCard label="Subdomains" value={String(parsedUrl.subdomain_count ?? 0)} />
                            <DetailCard label="Path" value={parsedUrl.path || '/'} />
                            <DetailCard label="Port" value={parsedUrl.port != null ? String(parsedUrl.port) : 'default'} />
                          </div>
                        </SectionBlock>
                      )}

                      {riskFactors.length > 0 && (
                        <SectionBlock title="Evidence breakdown">
                          <div className="space-y-3">
                            {riskFactors.map((factor, index) => (
                              <div key={`${factor.title}-${index}`} className="p-4 bg-[#06101D] border border-[#1B3557] rounded-2xl">
                                <div className="flex items-center justify-between gap-3 mb-2 flex-wrap">
                                  <div>
                                    <p className="text-white font-semibold">{factor.title}</p>
                                    <p className="text-[#8BA3BC] text-xs uppercase tracking-wide">{factor.category}</p>
                                  </div>
                                  <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${
                                    factor.severity === 'high'
                                      ? 'text-red-300 border-red-500/40 bg-red-500/10'
                                      : factor.severity === 'medium'
                                        ? 'text-amber-300 border-amber-500/40 bg-amber-500/10'
                                        : 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10'
                                  }`}>
                                    {factor.severity.toUpperCase()}
                                  </span>
                                </div>
                                <p className="text-[#D1E0EE] text-sm mb-2"><span className="text-white font-medium">Evidence:</span> {factor.evidence}</p>
                                <p className="text-[#98B3CD] text-sm"><span className="text-white font-medium">Why it matters:</span> {factor.impact}</p>
                              </div>
                            ))}
                          </div>
                        </SectionBlock>
                      )}

                      {(analysisDetails.detected_keywords?.length ?? 0) > 0 && (
                        <SectionBlock title="Detected keywords">
                          <div className="flex flex-wrap gap-2">
                            {analysisDetails.detected_keywords.map((keyword, index) => (
                              <Tag key={index}>{keyword}</Tag>
                            ))}
                          </div>
                        </SectionBlock>
                      )}

                      {recommendations.length > 0 && (
                        <SectionBlock title="Recommended action">
                          <div className="space-y-2">
                            {recommendations.map((recommendation, index) => (
                              <div key={index} className="p-3 bg-[#06101D] border border-[#1B3557] rounded-xl text-sm text-[#D1E0EE]">
                                {recommendation}
                              </div>
                            ))}
                          </div>
                        </SectionBlock>
                      )}
                    </Panel>
                  )}
                </div>

                <div className="space-y-6">
                  <Panel title="Dynamic runtime analysis" icon={<ShieldAlert className="w-4 h-4" />}>
                    <p className="text-[#D1E0EE] text-sm leading-relaxed mb-5">
                      {analysisDetails?.dynamic_summary || 'This section reflects what happened when the backend actually visited the URL and inspected the live response.'}
                    </p>

                    {screenshotData?.url && (
                      <SectionBlock title="Website screenshot">
                        <div className="rounded-2xl border border-[#1B3557] bg-[#06101D] p-3">
                          <img
                            src={screenshotData.url}
                            alt="Captured website screenshot"
                            className="w-full max-h-[560px] rounded-xl border border-[#1B3557] object-contain bg-black/20"
                            loading="lazy"
                          />
                        </div>
                      </SectionBlock>
                    )}

                    {!screenshotData?.url && screenshotData?.error && (
                      <SectionBlock title="Website screenshot">
                        <div className="p-4 bg-[#06101D] border border-[#1B3557] rounded-xl">
                          <p className="text-[#A7C1DB] text-sm">Screenshot capture: {screenshotData.error}</p>
                        </div>
                      </SectionBlock>
                    )}

                    {dynamicAnalysis?.available ? (
                      <>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
                          <DetailCard label="Dynamic score" value={`${dynamicAnalysis.dynamic_score}/45`} />
                          <DetailCard label="Final URL" value={dynamicAnalysis.final_url || 'n/a'} />
                          <DetailCard label="Redirect count" value={String(dynamicAnalysis.redirect_count ?? 0)} />
                          <DetailCard label="Page title" value={dynamicAnalysis.page?.title || 'n/a'} />
                          <DetailCard label="Password fields" value={String(dynamicAnalysis.page?.password_field_count ?? 0)} />
                          <DetailCard label="External form actions" value={String(dynamicAnalysis.page?.external_form_actions?.length ?? 0)} />
                        </div>

                        {dynamicAnalysis.flags?.length > 0 && (
                          <SectionBlock title="Runtime findings">
                            <div className="space-y-2">
                              {dynamicAnalysis.flags.map((flag, index) => (
                                <div key={index} className="p-3 bg-[#06101D] border border-[#1B3557] rounded-xl text-sm text-[#D1E0EE]">
                                  {flag}
                                </div>
                              ))}
                            </div>
                          </SectionBlock>
                        )}

                        {dynamicAnalysis.redirect_chain?.length > 0 && (
                          <SectionBlock title="Redirect chain">
                            <div className="space-y-2">
                              {dynamicAnalysis.redirect_chain.map((hop, index) => (
                                <div key={`${hop.url}-${index}`} className="p-3 bg-[#06101D] border border-[#1B3557] rounded-xl">
                                  <p className="text-white text-sm font-semibold">{hop.status_code} - {hop.host || 'unknown host'}</p>
                                  <p className="text-[#8BA3BC] text-xs break-all mt-1">{hop.url}</p>
                                </div>
                              ))}
                            </div>
                          </SectionBlock>
                        )}

                        {!!dynamicAnalysis.page?.external_form_actions?.length && (
                          <SectionBlock title="External form actions">
                            <div className="space-y-2">
                              {dynamicAnalysis.page.external_form_actions.map((action, index) => (
                                <div key={index} className="p-3 bg-[#06101D] border border-[#1B3557] rounded-xl text-sm text-[#D1E0EE] break-all">
                                  {action}
                                </div>
                              ))}
                            </div>
                          </SectionBlock>
                        )}
                      </>
                    ) : (
                      <div className="p-4 bg-[#06101D] border border-[#1B3557] rounded-xl">
                        <p className="text-white text-sm font-medium mb-2">Live fetch not available for this scan.</p>
                        <p className="text-[#8BA3BC] text-sm">{analysisDetails?.dynamic_error || 'The backend could not complete live runtime inspection, so the verdict is based on static and heuristic signals only.'}</p>
                      </div>
                    )}
                  </Panel>

                  <Panel title="Detection flags" icon={<AlertTriangle className="w-4 h-4" />}>
                    <div className="space-y-3">
                      {result.flags && result.flags.length > 0 ? (
                        result.flags.map((flag: string, index: number) => (
                          <div key={index} className="p-4 bg-[#06101D] border border-[#1B3557] rounded-xl">
                            <p className="text-white text-sm leading-relaxed">{flag}</p>
                          </div>
                        ))
                      ) : (
                        <div className="p-4 bg-[#06101D] border border-[#1B3557] rounded-xl">
                          <p className="text-[#8BA3BC] text-sm">No specific threats detected</p>
                        </div>
                      )}
                    </div>
                  </Panel>

                  <Panel title="Technical analysis" icon={<Gauge className="w-4 h-4" />}>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <DetailCard label="HTTPS" value={result.feature_summary?.is_https ? 'Enabled' : 'Disabled'} />
                      <DetailCard label="Suspicious TLD" value={result.feature_summary?.suspicious_tld ? 'Yes' : 'No'} />
                      <DetailCard label="IP address" value={result.feature_summary?.has_ip ? 'Used' : 'Domain'} />
                      <DetailCard label="URL shortener" value={result.feature_summary?.is_shortener ? 'Yes' : 'No'} />
                      <DetailCard label="Phishing keywords" value={`${result.feature_summary?.keyword_hits || 0} detected`} />
                      <DetailCard label="URL length" value={`${result.feature_summary?.url_length || 0} chars`} />
                    </div>
                  </Panel>
                </div>
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
