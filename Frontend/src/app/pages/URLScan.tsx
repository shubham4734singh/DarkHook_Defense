import { motion } from 'motion/react';
import { Shield, Link as LinkIcon, AlertTriangle, CheckCircle, XCircle, ArrowLeft, LogOut } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { useAuth } from '../contexts/AuthContext';import { api, type UrlScanResult } from '../services/api';import logo from '@/assets/eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png';

export function URLScan() {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<UrlScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const activeScreenshotRef = useRef<string | null>(null);
  const navigate = useNavigate();
  const { logout } = useAuth();

  const cleanupScreenshot = async (relativeUrl: string | null) => {
    if (!relativeUrl) {
      return;
    }

    try {
      await api.deleteUrlArtifact(relativeUrl);
    } catch (cleanupError) {
      console.warn('Failed to clean up screenshot artifact:', cleanupError);
    }
  };

  useEffect(() => {
    const screenshotRelativeUrl = result?.analysis_details?.dynamic_analysis?.screenshot?.relative_url ?? null;
    activeScreenshotRef.current = screenshotRelativeUrl;
  }, [result]);

  useEffect(() => {
    const handleBeforeUnload = () => {
      const relativeUrl = activeScreenshotRef.current;
      if (!relativeUrl) {
        return;
      }

      const payload = new Blob(
        [JSON.stringify({ relative_url: relativeUrl })],
        { type: 'application/json' },
      );
      navigator.sendBeacon?.(`${api.getBaseUrl()}/scan/url/artifact/delete`, payload);
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, []);

  useEffect(() => {
    return () => {
      const relativeUrl = activeScreenshotRef.current;
      activeScreenshotRef.current = null;
      if (relativeUrl) {
        void cleanupScreenshot(relativeUrl);
      }
    };
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const handleScan = async () => {
    if (!url) return;

    const previousScreenshot = activeScreenshotRef.current;
    activeScreenshotRef.current = null;
    if (previousScreenshot) {
      void cleanupScreenshot(previousScreenshot);
    }
    
    setScanning(true);
    setResult(null);
    setError(null);
    
    console.log('🚀 === SCAN START ===');
    console.log('Input URL:', url);
    
    try {
      // Call real API
      console.log('📍 Calling api.scanUrl()...');
      const response = await api.scanUrl(url);
      console.log('📍 Response received:', response);
      setResult(response);
      console.log('✅ === SCAN SUCCESS ===');
    } catch (error) {
      console.error('❌ === SCAN ERROR ===');
      console.error('Error object:', error);
      console.error('Error type:', typeof error);
      console.error('Error message:', error instanceof Error ? error.message : 'Unknown');
      setError(error instanceof Error ? error.message : 'Scan failed. Please try again.');
    } finally {
      setScanning(false);
    }
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
      case 'warning': return <AlertTriangle className="w-5 h-5" />;
      default: return <XCircle className="w-5 h-5" />;
    }
  };

  const analysisDetails = result?.analysis_details;
  const riskFactors = analysisDetails?.risk_factors ?? [];
  const recommendations = analysisDetails?.recommendations ?? [];
  const topRisks = analysisDetails?.top_risks ?? [];
  const parsedUrl = analysisDetails?.parsed_url;
  const dynamicAnalysis = analysisDetails?.dynamic_analysis;
  const confidenceLabel = result?.status === 'safe' ? 'Verdict Confidence' : 'Detection Confidence';

  return (
    <div className="min-h-screen bg-[#060D1A]">
      {/* Navbar */}
      <nav className="fixed top-0 left-0 right-0 z-50 h-[68px] bg-[#0D1F38]/95 backdrop-blur-xl border-b border-[#1E3A5F]">
        <div className="max-w-[1440px] mx-auto px-4 h-full flex items-center justify-between">
          {/* Logo */}
          <Link to="/dashboard" className="flex items-center gap-2 cursor-pointer">
            <img src={logo} alt="Darkhook Defense" className="h-14" />
          </Link>

          {/* Nav Items */}
          <div className="flex items-center gap-6">
            <Link
              to="/dashboard"
              className="flex items-center gap-2 text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span className="hidden sm:inline">Dashboard</span>
            </Link>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-4 py-2 text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span className="hidden sm:inline">Logout</span>
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="pt-[100px] py-16 px-4">
        <div className="max-w-6xl mx-auto">
          {/* Page Header */}
          <div className="mb-8">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 bg-[#0D1F38] rounded-xl flex items-center justify-center border border-[#1E3A5F]">
                <LinkIcon className="w-6 h-6 text-[#00C2FF]" />
              </div>
              <div>
                <h1 className="text-3xl font-bold text-white">URL Scanner</h1>
                <p className="text-[#8BA3BC]">Check URLs for phishing and malicious content</p>
              </div>
            </div>
          </div>

          {/* Scanner Card */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8 mb-8"
          >
            <div className="mb-6">
              <label className="block text-white font-semibold mb-3">
                Enter URL to scan
              </label>
              <input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full px-4 py-3 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-white placeholder-[#8BA3BC] focus:outline-none focus:border-[#00C2FF] focus:ring-2 focus:ring-[#00C2FF]/30 transition-all"
              />
            </div>

            <button
              onClick={handleScan}
              disabled={!url || scanning}
              className="w-full px-6 py-3 bg-[#00C2FF] hover:bg-[#00A8E0] text-[#060D1A] font-semibold rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_24px_rgba(0,194,255,0.35)]"
            >
              {scanning ? 'Scanning...' : 'Scan URL'}
            </button>
          </motion.div>

          {/* Error Message */}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="mb-8 p-4 bg-red-900/30 border border-red-500/50 rounded-lg"
            >
              <div className="flex items-center gap-3">
                <XCircle className="w-5 h-5 text-red-400 shrink-0" />
                <p className="text-red-300 text-sm">{error}</p>
              </div>
            </motion.div>
          )}

          {/* Results */}
          {result && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-6"
            >
              {/* Risk Score Card */}
              <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8">
                <div className="text-center mb-6">
                  <div className="flex justify-center mb-3" style={{ color: getStatusColor(result.status) }}>
                    {getStatusIcon(result.status)}
                  </div>
                  <div className="inline-flex items-center justify-center w-32 h-32 rounded-full border-8 mb-4"
                    style={{ borderColor: getStatusColor(result.status) }}>
                    <span className="text-4xl font-bold text-white">{result.score}</span>
                  </div>
                  <h3 className="text-2xl font-bold mb-2" style={{ color: getStatusColor(result.status) }}>
                    {result.status === 'safe' ? '🟢 SAFE' : result.status === 'suspicious' ? '🟡 SUSPICIOUS' : '🔴 PHISHING'}
                  </h3>
                  <p className="text-[#8BA3BC] mb-4">
                    {result.verdict} - {confidenceLabel}: {(result.confidence * 100).toFixed(0)}%
                  </p>
                  <p className="text-[#8BA3BC] text-sm">
                    {result.explanation}
                  </p>
                </div>
              </div>

              <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8">
                <h3 className="text-xl font-bold text-white mb-4">Scan Snapshot</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
                  <DetailCard label="Scanned URL" value={result.url} />
                  <DetailCard label="Host" value={parsedUrl?.hostname || 'n/a'} />
                  <DetailCard label="Dynamic Status" value={analysisDetails?.dynamic_status || 'unavailable'} />
                  <DetailCard label="Keyword Hits" value={String(result.feature_summary?.keyword_hits || 0)} />
                </div>
              </div>

              <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                {analysisDetails && (
                <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8 h-full">
                  <div className="flex items-start justify-between gap-4 mb-5 flex-wrap">
                    <div>
                      <h3 className="text-xl font-bold text-white mb-2">Detailed Assessment</h3>
                      <p className="text-[#8BA3BC] text-sm leading-relaxed max-w-3xl">
                        {analysisDetails.summary}
                      </p>
                    </div>
                    <div className="px-4 py-2 rounded-lg bg-[#060D1A] border border-[#1E3A5F]">
                      <p className="text-[#8BA3BC] text-xs mb-1">Analysis Engine</p>
                      <p className="text-white text-sm font-semibold">{analysisDetails.model_source}</p>
                    </div>
                  </div>

                  {topRisks.length > 0 && (
                    <div className="mb-6">
                      <h4 className="text-white font-semibold mb-3">Top Risk Drivers</h4>
                      <div className="flex flex-wrap gap-2">
                        {topRisks.map((risk, index) => (
                          <span key={index} className="px-3 py-2 bg-[#060D1A] border border-[#1E3A5F] rounded-full text-sm text-[#A9CBE0]">
                            {risk}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {parsedUrl && (
                    <div className="mb-6">
                      <h4 className="text-white font-semibold mb-3">Parsed URL</h4>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <DetailCard label="Scheme" value={parsedUrl.scheme || 'n/a'} />
                        <DetailCard label="Hostname" value={parsedUrl.hostname || 'n/a'} />
                        <DetailCard label="Base Domain" value={parsedUrl.base_domain || 'n/a'} />
                        <DetailCard label="Subdomains" value={String(parsedUrl.subdomain_count ?? 0)} />
                        <DetailCard label="Path" value={parsedUrl.path || '/'} />
                        <DetailCard label="Port" value={parsedUrl.port != null ? String(parsedUrl.port) : 'default'} />
                      </div>
                    </div>
                  )}

                  {riskFactors.length > 0 && (
                    <div className="mb-6">
                      <h4 className="text-white font-semibold mb-3">Evidence Breakdown</h4>
                      <div className="space-y-3">
                        {riskFactors.map((factor, index) => (
                          <div key={`${factor.title}-${index}`} className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg">
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
                            <p className="text-[#C8D5E2] text-sm mb-2"><span className="text-white font-medium">Evidence:</span> {factor.evidence}</p>
                            <p className="text-[#8BA3BC] text-sm"><span className="text-white font-medium">Why it matters:</span> {factor.impact}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {(analysisDetails.detected_keywords?.length ?? 0) > 0 && (
                    <div className="mb-6">
                      <h4 className="text-white font-semibold mb-3">Detected Keywords</h4>
                      <div className="flex flex-wrap gap-2">
                        {analysisDetails.detected_keywords.map((keyword, index) => (
                          <span key={index} className="px-3 py-1.5 rounded-full bg-[#060D1A] border border-[#1E3A5F] text-[#A9CBE0] text-sm">
                            {keyword}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {recommendations.length > 0 && (
                    <div>
                      <h4 className="text-white font-semibold mb-3">Recommended Action</h4>
                      <div className="space-y-2">
                        {recommendations.map((recommendation, index) => (
                          <div key={index} className="p-3 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-sm text-[#C8D5E2]">
                            {recommendation}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {analysisDetails && (
                <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8 h-full">
                  <div className="flex items-start justify-between gap-4 mb-5 flex-wrap">
                    <div>
                      <h3 className="text-xl font-bold text-white mb-2">Dynamic Runtime Analysis</h3>
                      <p className="text-[#8BA3BC] text-sm leading-relaxed">
                        {analysisDetails.dynamic_summary || 'This section reflects what happened when the backend actually visited the URL and inspected the live response.'}
                      </p>
                    </div>
                    <div className="px-4 py-2 rounded-lg bg-[#060D1A] border border-[#1E3A5F]">
                      <p className="text-[#8BA3BC] text-xs mb-1">Dynamic Status</p>
                      <p className="text-white text-sm font-semibold">{analysisDetails.dynamic_status || (dynamicAnalysis?.available ? 'available' : 'unavailable')}</p>
                    </div>
                  </div>

                  {dynamicAnalysis?.available ? (
                    <>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
                        <DetailCard label="Dynamic Score" value={`${dynamicAnalysis.dynamic_score}/45`} />
                        <DetailCard label="Final URL" value={dynamicAnalysis.final_url || 'n/a'} />
                        <DetailCard label="Redirect Count" value={String(dynamicAnalysis.redirect_count ?? 0)} />
                        <DetailCard label="Page Title" value={dynamicAnalysis.page?.title || 'n/a'} />
                        <DetailCard label="Password Fields" value={String(dynamicAnalysis.page?.password_field_count ?? 0)} />
                        <DetailCard label="External Form Actions" value={String(dynamicAnalysis.page?.external_form_actions?.length ?? 0)} />
                      </div>

                      {dynamicAnalysis.flags?.length > 0 && (
                        <div className="mb-6">
                          <h4 className="text-white font-semibold mb-3">Runtime Findings</h4>
                          <div className="space-y-2">
                            {dynamicAnalysis.flags.map((flag, index) => (
                              <div key={index} className="p-3 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-sm text-[#C8D5E2]">
                                {flag}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {dynamicAnalysis.screenshot?.url && (
                        <div className="mb-6">
                          <h4 className="text-white font-semibold mb-3">Website Screenshot</h4>
                          <div className="p-3 bg-[#060D1A] border border-[#1E3A5F] rounded-xl">
                            <img
                              src={dynamicAnalysis.screenshot.url}
                              alt="Captured website screenshot"
                              className="w-full rounded-lg border border-[#1E3A5F] object-cover"
                              loading="lazy"
                            />
                          </div>
                        </div>
                      )}

                      {dynamicAnalysis.redirect_chain?.length > 0 && (
                        <div className="mb-6">
                          <h4 className="text-white font-semibold mb-3">Redirect Chain</h4>
                          <div className="space-y-2">
                            {dynamicAnalysis.redirect_chain.map((hop, index) => (
                              <div key={`${hop.url}-${index}`} className="p-3 bg-[#060D1A] border border-[#1E3A5F] rounded-lg">
                                <p className="text-white text-sm font-semibold">{hop.status_code} - {hop.host || 'unknown host'}</p>
                                <p className="text-[#8BA3BC] text-xs break-all mt-1">{hop.url}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {!!dynamicAnalysis.page?.external_form_actions?.length && (
                        <div>
                          <h4 className="text-white font-semibold mb-3">External Form Actions</h4>
                          <div className="space-y-2">
                            {dynamicAnalysis.page.external_form_actions.map((action, index) => (
                              <div key={index} className="p-3 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-sm text-[#C8D5E2] break-all">
                                {action}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="mb-6">
                      <h4 className="text-white font-semibold mb-3">Runtime Status</h4>
                      <div className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg">
                        <p className="text-white text-sm font-medium mb-2">Live fetch not available for this scan.</p>
                        <p className="text-[#8BA3BC] text-sm">
                          {analysisDetails.dynamic_error || 'The backend could not complete live runtime inspection, so the verdict is based on static and heuristic signals only.'}
                        </p>
                        {dynamicAnalysis?.screenshot?.error && (
                          <p className="text-[#8BA3BC] text-sm mt-2">
                            Screenshot capture: {dynamicAnalysis.screenshot.error}
                          </p>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}
              </div>

              {/* Detection Flags */}
              <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8">
                <h3 className="text-xl font-bold text-white mb-4">Detection Flags</h3>
                <div className="space-y-3">
                  {result.flags && result.flags.length > 0 ? (
                    result.flags.map((flag: string, index: number) => (
                      <div
                        key={index}
                        className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg"
                      >
                        <p className="text-white text-sm leading-relaxed">{flag}</p>
                      </div>
                    ))
                  ) : (
                    <div className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg">
                      <p className="text-[#8BA3BC] text-sm">No specific threats detected</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Technical Details */}
              <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8">
                <h3 className="text-xl font-bold text-white mb-4">Technical Analysis</h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg">
                    <p className="text-[#8BA3BC] text-xs mb-1">HTTPS</p>
                    <p className="text-white font-semibold">{result.feature_summary?.is_https ? '✓ Enabled' : '✗ Disabled'}</p>
                  </div>
                  <div className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg">
                    <p className="text-[#8BA3BC] text-xs mb-1">Suspicious TLD</p>
                    <p className="text-white font-semibold">{result.feature_summary?.suspicious_tld ? '⚠️ Yes' : '✓ No'}</p>
                  </div>
                  <div className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg">
                    <p className="text-[#8BA3BC] text-xs mb-1">IP Address</p>
                    <p className="text-white font-semibold">{result.feature_summary?.has_ip ? '⚠️ Used' : '✓ Domain'}</p>
                  </div>
                  <div className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg">
                    <p className="text-[#8BA3BC] text-xs mb-1">URL Shortener</p>
                    <p className="text-white font-semibold">{result.feature_summary?.is_shortener ? '⚠️ Yes' : '✓ No'}</p>
                  </div>
                  <div className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg">
                    <p className="text-[#8BA3BC] text-xs mb-1">Phishing Keywords</p>
                    <p className="text-white font-semibold">{result.feature_summary?.keyword_hits || 0} detected</p>
                  </div>
                  <div className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg">
                    <p className="text-[#8BA3BC] text-xs mb-1">URL Length</p>
                    <p className="text-white font-semibold">{result.feature_summary?.url_length || 0} chars</p>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
}

function DetailCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg">
      <p className="text-[#8BA3BC] text-xs mb-1">{label}</p>
      <p className="text-white font-semibold break-all">{value}</p>
    </div>
  );
}
