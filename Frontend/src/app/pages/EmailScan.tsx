import { motion } from 'motion/react';
import { Shield, Mail, Upload, AlertTriangle, CheckCircle, XCircle, ArrowLeft, LogOut, Printer } from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { useAuth } from '../contexts/AuthContext';
import { api, type EmailScanResult } from '../services/api';
import { SecurityReportModal, type SecurityReportData } from '../components/SecurityReportModal';
import logo from '@/assets/eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png';

export function EmailScan() {
  const [emailContent, setEmailContent] = useState('');
  const [emailFile, setEmailFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<EmailScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showReportModal, setShowReportModal] = useState(false);
  const navigate = useNavigate();
  const { logout } = useAuth();

  const reportData: SecurityReportData | null = result ? {
    reportId: `DHD-EML-${Math.random().toString(36).substring(2, 9).toUpperCase()}`,
    scanType: 'EMAIL',
    targetName: result.fileName || (emailFile ? emailFile.name : 'pasted-email.eml'),
    scanTimestamp: new Date().toLocaleString(),
    durationSeconds: result.scanTime,
    verdict: (result.verdict?.toUpperCase() === 'SAFE' ? 'SAFE' : result.verdict?.toUpperCase() === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'PHISHING'),
    riskScore: result.riskScore,
    findings: [
      ...result.headerFlags.map((flag) => ({
        title: flag,
        severity: (result.riskScore > 70 ? 'critical' : result.riskScore > 40 ? 'high' : 'medium') as any,
        category: 'Header Authentication & Routing',
        evidence: `RFC header verification flag: ${flag}`,
        impact: 'Potential email spoofing, SPF/DKIM failure, or domain impersonation',
        mitreId: 'T1566.001',
      })),
      ...result.bodyFlags.map((flag) => ({
        title: flag,
        severity: (result.riskScore > 70 ? 'high' : 'medium') as any,
        category: 'Email Body & Social Engineering',
        evidence: `Body content inspection flag: ${flag}`,
        impact: 'Deceptive narrative, urgent call-to-action, or credential harvest bait',
        mitreId: 'T1566.002',
      })),
    ],
    extractedUrls: (result.extractedUrls || []).map((u) => ({
      url: u,
      domain: (() => {
        try { return new URL(u).hostname; } catch { return u; }
      })(),
      isSuspicious: result.riskScore > 50,
      reasons: result.riskScore > 50 ? ['Suspicious link inside unverified email body'] : [],
    })),
    recommendations: result.verdict === 'SAFE' ? [
      'Email headers and content passed standard anti-phishing heuristics.',
      'Exercise normal caution before downloading unverified attachments.',
      'Report any unexpected behavioral anomalies to your SOC administrator.',
    ] : [
      'Quarantine or delete this email immediately; do NOT interact with embedded hyperlinks or attachments.',
      'Verify the sender through a secondary out-of-band communication channel (e.g. phone call or internal chat).',
      'If credentials or sensitive information were provided, reset accounts immediately and revoke active sessions.',
      'Submit the email headers and raw source to the security operations center (SOC) for domain-wide blocklisting.',
    ],
    summary: `Comprehensive email forensic analysis completed for "${result.fileName || 'analyzed email'}". Identified ${result.headerFlags.length} header flags, ${result.bodyFlags.length} body indicators, and ${result.extractedUrls?.length || 0} embedded URLs.`,
  } : null;

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const handleScan = async () => {
    setError(null);
    setResult(null);
    setScanning(true);

    try {
      const fileToScan = emailFile || new File([emailContent], 'pasted-email.eml', { type: 'message/rfc822' });
      const data = await api.scanEmail(fileToScan);
      setResult(data);
    } catch (scanError: any) {
      setError(scanError?.message || 'Email scan failed');
    } finally {
      setScanning(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setEmailFile(file);
      const reader = new FileReader();
      reader.onload = (event) => {
        setEmailContent(event.target?.result as string);
      };
      reader.readAsText(file);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'SAFE': return '#00D68F';
      case 'SUSPICIOUS': return '#FFAA00';
      case 'PHISHING': return '#FF3B3B';
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
        <div className="max-w-4xl mx-auto">
          {/* Page Header */}
          <div className="mb-8">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 bg-[#0D1F38] rounded-xl flex items-center justify-center border border-[#1E3A5F]">
                <Mail className="w-6 h-6 text-[#00C2FF]" />
              </div>
              <div>
                <h1 className="text-3xl font-bold text-white">Email Scanner</h1>
                <p className="text-[#8BA3BC]">Analyze emails for phishing and malicious content</p>
              </div>
            </div>
          </div>

          {/* Scanner Card */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8 mb-8"
          >
            {/* File Upload */}
            <div className="mb-6">
              <label className="block text-white font-semibold mb-3">
                Upload .eml file or paste email content
              </label>
              <div className="relative">
                <input
                  type="file"
                  accept=".eml"
                  onChange={handleFileUpload}
                  className="hidden"
                  id="email-upload"
                />
                <label
                  htmlFor="email-upload"
                  className="flex items-center justify-center gap-3 px-6 py-4 bg-[#060D1A] border-2 border-dashed border-[#1E3A5F] rounded-lg cursor-pointer hover:border-[#00C2FF] transition-all"
                >
                  <Upload className="w-5 h-5 text-[#00C2FF]" />
                  <span className="text-[#8BA3BC]">Click to upload .eml file</span>
                </label>
              </div>
            </div>

            <div className="text-center text-[#8BA3BC] mb-4">OR</div>

            {/* Text Area */}
            <div className="mb-6">
              <textarea
                value={emailContent}
                onChange={(e) => setEmailContent(e.target.value)}
                placeholder="Paste email content here..."
                rows={8}
                className="w-full px-4 py-3 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-white placeholder-[#8BA3BC] focus:outline-none focus:border-[#00C2FF] focus:ring-2 focus:ring-[#00C2FF]/30 transition-all resize-none"
              />
            </div>

            <button
              onClick={handleScan}
              disabled={(!emailContent && !emailFile) || scanning}
              className="w-full px-6 py-3 bg-[#00C2FF] hover:bg-[#00A8E0] text-[#060D1A] font-semibold rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_24px_rgba(0,194,255,0.35)]"
            >
              {scanning ? 'Scanning...' : 'Scan Email'}
            </button>
            {error && <p className="mt-3 text-sm text-[#FF6B6B]">{error}</p>}
          </motion.div>

          {/* Results */}
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
                    onClick={() => setShowReportModal(true)}
                    className="flex items-center gap-1.5 px-3.5 py-1.5 bg-gradient-to-r from-[#00C2FF]/20 to-[#0077B6]/20 border border-[#00C2FF]/40 hover:border-[#00C2FF] text-[#00C2FF] hover:text-white rounded-lg text-xs font-semibold shadow-sm transition-all"
                  >
                    <Printer className="w-3.5 h-3.5" />
                    <span>Print / Export Security Report</span>
                  </button>
                </div>
              </div>

              {/* Risk Score Card */}
              <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8">
                <div className="text-center mb-6">
                  <div className="inline-flex items-center justify-center w-32 h-32 rounded-full border-8 mb-4"
                    style={{ borderColor: getStatusColor(result.verdict) }}>
                    <span className="text-4xl font-bold text-white">{result.riskScore}</span>
                  </div>
                  <h3 className="text-2xl font-bold mb-2" style={{ color: getStatusColor(result.verdict) }}>
                    {result.verdict === 'SAFE' ? 'SAFE' : result.verdict === 'PHISHING' ? 'PHISHING' : 'SUSPICIOUS'}
                  </h3>
                  <p className="text-[#8BA3BC]">
                    {result.verdict === 'SAFE' ? 'No threats detected' : result.verdict === 'PHISHING' ? 'Do not trust this email' : 'Proceed with caution'}
                  </p>
                </div>
              </div>

              {/* Threat Details */}
              <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8">
                <h3 className="text-xl font-bold text-white mb-4">Email Analysis</h3>
                <div className="space-y-3">
                  {[...result.headerFlags, ...result.bodyFlags].map((threat: string, index: number) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg"
                    >
                      <span className="text-white font-medium">{threat}</span>
                      <div className="flex items-center gap-2" style={{ color: getStatusColor(result.verdict) }}>
                        {getStatusIcon(result.verdict === 'SAFE' ? 'safe' : 'warning')}
                        <span className="text-sm font-semibold uppercase">{result.verdict === 'SAFE' ? 'safe' : 'warning'}</span>
                      </div>
                    </div>
                  ))}
                  {result.headerFlags.length === 0 && result.bodyFlags.length === 0 && (
                    <div className="p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-[#8BA3BC]">
                      No suspicious header/body flags were detected.
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          )}

          {reportData && (
            <SecurityReportModal
              isOpen={showReportModal}
              onClose={() => setShowReportModal(false)}
              data={reportData}
            />
          )}
        </div>
      </div>
    </div>
  );
}