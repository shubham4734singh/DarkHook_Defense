import React from 'react';
import {
  Printer,
  FileDown,
  X,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  Hash,
  Layers,
  Globe,
  ExternalLink,
  CheckCircle2,
  AlertOctagon,
} from 'lucide-react';
import logo from '@/assets/164bd3b4c66bb15268339b22ae1165b91c7ea4e9.png';

export interface ReportFinding {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category?: string;
  evidence?: string;
  impact?: string;
  mitreId?: string;
}

export interface ReportMitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
}

export interface ReportExtractedUrl {
  url: string;
  domain?: string;
  isSuspicious: boolean;
  reasons?: string[];
}

export interface SecurityReportData {
  reportId: string;
  scanType: 'URL' | 'DOCUMENT' | 'EMAIL';
  targetName: string;
  scanTimestamp: string;
  durationSeconds?: number;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'PHISHING';
  riskScore: number; // 0 - 100
  confidence?: number; // 0 - 1
  sha256Hash?: string;
  fileSize?: string;
  findings: ReportFinding[];
  mitreTechniques?: ReportMitreTechnique[];
  extractedUrls?: ReportExtractedUrl[];
  recommendations?: string[];
  summary?: string;
  telemetry?: {
    redirectCount?: number;
    tlsValid?: boolean;
    formCount?: number;
    passwordFieldCount?: number;
    spf?: string;
    dkim?: string;
    dmarc?: string;
  };
}

interface SecurityReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  data: SecurityReportData;
}

export function SecurityReportModal({ isOpen, onClose, data }: SecurityReportModalProps) {
  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJson = () => {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `DarkHook-Report-${data.reportId}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getVerdictStyle = () => {
    switch (data.verdict) {
      case 'SAFE':
        return {
          badgeBg: '#e6fbf2',
          badgeBorder: '#00d68f',
          textColor: '#047857',
          icon: <ShieldCheck className="w-6 h-6 text-emerald-600" />,
          title: 'CLEAN / BENIGN',
          subtitle: 'No malicious signatures or structural threats detected',
        };
      case 'SUSPICIOUS':
        return {
          badgeBg: '#fff8eb',
          badgeBorder: '#f59e0b',
          textColor: '#b45309',
          icon: <AlertTriangle className="w-6 h-6 text-amber-600" />,
          title: 'SUSPICIOUS ACTIVITY DETECTED',
          subtitle: 'Anomalous patterns or deceptive elements identified',
        };
      case 'PHISHING':
      default:
        return {
          badgeBg: '#fef2f2',
          badgeBorder: '#ef4444',
          textColor: '#b91c1c',
          icon: <AlertOctagon className="w-6 h-6 text-red-600" />,
          title: 'MALICIOUS / PHISHING THREAT',
          subtitle: 'Critical threat indicators detected. High probability of attack',
        };
    }
  };

  const verdictStyle = getVerdictStyle();

  return (
    <div
      className={`security-report-modal-root fixed inset-0 z-[9999] overflow-y-auto bg-black/80 backdrop-blur-md items-center justify-center p-2 sm:p-6 print:p-0 print:bg-white print:static ${
        isOpen ? 'flex' : 'hidden print:block'
      }`}
    >
      {/* Container Dialog */}
      <div className="bg-[#0B1528] border border-[#1E3A5F] w-full max-w-4xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh] print:max-h-none print:border-none print:shadow-none print:w-full print:rounded-none">
        
        {/* Top Floating Action Bar (Hidden in Print) */}
        <div className="no-print bg-[#0D1F38] border-b border-[#1E3A5F] px-6 py-4 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-[#00C2FF]" />
            <h2 className="text-white font-bold text-base">Security Assessment Report Preview</h2>
            <span className="ml-2 text-xs bg-[#00C2FF]/10 text-[#00C2FF] border border-[#00C2FF]/30 px-2 py-0.5 rounded font-mono">
              {data.reportId}
            </span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handlePrint}
              className="flex items-center gap-2 px-4 py-2 bg-[#00C2FF] hover:bg-[#00A8E0] text-[#060D1A] text-xs font-bold rounded-lg transition-all shadow-[0_0_15px_rgba(0,194,255,0.3)]"
            >
              <Printer className="w-4 h-4" />
              <span>Print / Save as PDF</span>
            </button>

            <button
              onClick={handleDownloadJson}
              className="flex items-center gap-1.5 px-3 py-2 bg-[#10243E] hover:bg-[#18355A] text-[#8BA3BC] hover:text-white border border-[#1E3A5F] text-xs font-semibold rounded-lg transition-all"
            >
              <FileDown className="w-4 h-4" />
              <span>Export JSON</span>
            </button>

            <button
              onClick={onClose}
              className="p-2 text-[#8BA3BC] hover:text-white hover:bg-white/10 rounded-lg transition-all"
              title="Close"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Scrollable Report Sheet Preview */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-8 bg-[#070E1A] print:p-0 print:bg-white print:overflow-visible">
          
          {/* THE OFFICIAL PRINTABLE AUDIT SHEET (Clean White Paper Style) */}
          <div
            id="printable-security-report"
            className="bg-white text-[#111827] max-w-[850px] mx-auto p-8 sm:p-12 rounded-xl shadow-lg border border-slate-200 print:shadow-none print:border-none print:p-0 print:m-0 print:max-w-none"
            style={{ fontFamily: 'system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif' }}
          >
            {/* Header / Document Identity */}
            <div className="border-b-2 border-slate-900 pb-6 mb-6">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-3 mb-1">
                    <img src={logo} alt="DarkHook Defense" className="h-10 w-auto filter grayscale contrast-200" />
                    <div>
                      <h1 className="text-2xl font-extrabold tracking-tight text-slate-950 uppercase">
                        DarkHook Defense
                      </h1>
                      <p className="text-[10px] font-bold text-slate-500 tracking-widest uppercase">
                        AI Multi-Modal Phishing Detection & Threat Intelligence
                      </p>
                    </div>
                  </div>
                </div>

                <div className="text-right shrink-0">
                  <span className="inline-block bg-slate-900 text-white text-[10px] font-black uppercase px-2.5 py-1 tracking-wider rounded">
                    SECURITY ASSESSMENT REPORT
                  </span>
                  <p className="text-xs text-slate-600 font-mono mt-1.5 font-bold">ID: {data.reportId}</p>
                  <p className="text-[11px] text-slate-500">{data.scanTimestamp}</p>
                </div>
              </div>
            </div>

            {/* Target Information Bar */}
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 mb-6">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
                <div>
                  <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block mb-0.5">
                    Modality / Target Type
                  </span>
                  <span className="font-bold text-slate-900">{data.scanType} SCAN</span>
                </div>
                <div className="md:col-span-2">
                  <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block mb-0.5">
                    Analyzed Target
                  </span>
                  <span className="font-mono text-slate-900 break-all text-[11px] font-semibold">
                    {data.targetName}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block mb-0.5">
                    Engine Processing Time
                  </span>
                  <span className="font-semibold text-slate-800">
                    {data.durationSeconds ? `${data.durationSeconds.toFixed(3)}s` : 'Real-time (<1s)'}
                  </span>
                </div>
              </div>

              {data.sha256Hash && (
                <div className="mt-3 pt-3 border-t border-slate-200 flex items-center justify-between text-[11px]">
                  <span className="text-slate-500 font-semibold">SHA-256 Checksum:</span>
                  <span className="font-mono text-slate-700 bg-white border border-slate-300 px-2 py-0.5 rounded text-[10px]">
                    {data.sha256Hash}
                  </span>
                </div>
              )}
            </div>

            {/* Executive Verdict Banner */}
            <div
              className="rounded-lg p-5 mb-6 border-2 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              style={{
                backgroundColor: verdictStyle.badgeBg,
                borderColor: verdictStyle.badgeBorder,
              }}
            >
              <div className="flex items-center gap-4">
                <div className="p-2 bg-white rounded-lg border border-slate-200 shadow-sm">
                  {verdictStyle.icon}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-black uppercase tracking-wider text-slate-600">
                      Overall Verdict:
                    </span>
                    <span
                      className="text-base font-black uppercase tracking-tight"
                      style={{ color: verdictStyle.textColor }}
                    >
                      {verdictStyle.title}
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 mt-0.5">{verdictStyle.subtitle}</p>
                </div>
              </div>

              <div className="sm:text-right border-t sm:border-t-0 sm:border-l border-slate-300/60 pt-3 sm:pt-0 sm:pl-6 shrink-0">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">
                  Threat Risk Score
                </span>
                <div className="flex items-baseline gap-1 sm:justify-end">
                  <span
                    className="text-3xl font-black"
                    style={{ color: verdictStyle.textColor }}
                  >
                    {data.riskScore}
                  </span>
                  <span className="text-xs font-bold text-slate-400">/ 100</span>
                </div>
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-600 block">
                  {data.riskScore >= 70 ? 'High Risk' : data.riskScore >= 35 ? 'Moderate Risk' : 'Low / Clean'}
                </span>
              </div>
            </div>

            {/* Summary Text if present */}
            {data.summary && (
              <div className="mb-6 p-4 bg-slate-50 border-l-4 border-slate-800 rounded-r-lg text-xs leading-relaxed text-slate-700">
                <span className="font-bold text-slate-900 block mb-1">Executive Summary:</span>
                {data.summary}
              </div>
            )}

            {/* Section: Detected Threat Indicators / Findings */}
            <div className="mb-6">
              <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-300">
                <h3 className="text-sm font-extrabold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-slate-700" />
                  <span>Detected Threat Indicators ({data.findings.length})</span>
                </h3>
                <span className="text-[11px] text-slate-500">Ranked by risk weight</span>
              </div>

              {data.findings.length > 0 ? (
                <div className="border border-slate-200 rounded-lg overflow-hidden">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-slate-100 text-slate-700 border-b border-slate-200 font-bold text-[11px] uppercase">
                        <th className="py-2.5 px-3 w-24">Severity</th>
                        <th className="py-2.5 px-3">Indicator / Finding</th>
                        <th className="py-2.5 px-3">Technical Evidence / Context</th>
                        <th className="py-2.5 px-3">Potential Impact</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200">
                      {data.findings.map((item, idx) => (
                        <tr key={idx} className="hover:bg-slate-50/80">
                          <td className="py-2.5 px-3 align-top">
                            <span
                              className={`inline-block px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider border ${
                                item.severity === 'critical'
                                  ? 'bg-red-100 text-red-800 border-red-300'
                                  : item.severity === 'high'
                                  ? 'bg-rose-100 text-rose-800 border-rose-300'
                                  : item.severity === 'medium'
                                  ? 'bg-amber-100 text-amber-800 border-amber-300'
                                  : 'bg-blue-100 text-blue-800 border-blue-300'
                              }`}
                            >
                              {item.severity}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 align-top font-bold text-slate-900">
                            {item.title}
                            {item.category && (
                              <span className="block text-[10px] text-slate-500 font-normal mt-0.5">
                                Category: {item.category}
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-3 align-top text-slate-700 font-mono text-[11px] break-all leading-snug">
                            {item.evidence || 'Pattern recognized by heuristic rules'}
                          </td>
                          <td className="py-2.5 px-3 align-top text-slate-600 text-[11px] leading-snug">
                            {item.impact || 'Credential theft / unauthorized execution'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-lg text-xs text-emerald-800 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span>No structural, lexical, or payload threat indicators detected.</span>
                </div>
              )}
            </div>

            {/* Section: MITRE ATT&CK Mapping (if present) */}
            {data.mitreTechniques && data.mitreTechniques.length > 0 && (
              <div className="mb-6">
                <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-300">
                  <h3 className="text-sm font-extrabold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                    <Layers className="w-4 h-4 text-slate-700" />
                    <span>MITRE ATT&CK® Threat Tactics Identified</span>
                  </h3>
                  <span className="text-[11px] text-slate-500">Enterprise Matrix v14</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {data.mitreTechniques.map((tech, idx) => (
                    <div key={idx} className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-mono font-bold text-slate-900 bg-white border border-slate-300 px-2 py-0.5 rounded text-[10px]">
                          {tech.id}
                        </span>
                        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                          {tech.tactic}
                        </span>
                      </div>
                      <p className="font-bold text-slate-900 text-[11px] mb-0.5">{tech.name}</p>
                      <p className="text-slate-600 text-[10px] leading-tight">{tech.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Section: Extracted Outbound Links / IoCs (if present) */}
            {data.extractedUrls && data.extractedUrls.length > 0 && (
              <div className="mb-6">
                <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-300">
                  <h3 className="text-sm font-extrabold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                    <Globe className="w-4 h-4 text-slate-700" />
                    <span>Extracted Outbound Endpoints & IoCs ({data.extractedUrls.length})</span>
                  </h3>
                </div>

                <div className="border border-slate-200 rounded-lg overflow-hidden text-xs">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-slate-100 text-slate-700 text-[10px] uppercase font-bold border-b border-slate-200">
                        <th className="py-2 px-3">Status</th>
                        <th className="py-2 px-3">Extracted URL</th>
                        <th className="py-2 px-3">Base Domain</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 text-[11px]">
                      {data.extractedUrls.slice(0, 10).map((u, idx) => (
                        <tr key={idx}>
                          <td className="py-2 px-3">
                            <span
                              className={`inline-block px-1.5 py-0.5 rounded text-[9px] font-black uppercase ${
                                u.isSuspicious
                                  ? 'bg-red-100 text-red-800 border border-red-300'
                                  : 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                              }`}
                            >
                              {u.isSuspicious ? 'Suspicious' : 'Clean'}
                            </span>
                          </td>
                          <td className="py-2 px-3 font-mono text-slate-800 break-all">{u.url}</td>
                          <td className="py-2 px-3 font-mono text-slate-600">{u.domain || 'N/A'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Section: Actionable Security Recommendations */}
            <div className="mb-6">
              <div className="pb-2 mb-3 border-b border-slate-300">
                <h3 className="text-sm font-extrabold text-slate-900 uppercase tracking-wider">
                  Recommended Incident Response Actions
                </h3>
              </div>

              <div className="space-y-2 text-xs text-slate-700">
                {data.verdict === 'PHISHING' ? (
                  <>
                    <div className="p-2.5 bg-red-50 border-l-4 border-red-600 text-red-900 rounded-r flex items-start gap-2">
                      <span className="font-bold">1. Block Destination:</span>
                      <span>Immediately add the domain/URL or file hash to gateway firewall and EDR blocklists.</span>
                    </div>
                    <div className="p-2.5 bg-red-50 border-l-4 border-red-600 text-red-900 rounded-r flex items-start gap-2">
                      <span className="font-bold">2. Credential Invalidation:</span>
                      <span>If user credentials were typed or submitted, force immediate password reset and revoke active session tokens.</span>
                    </div>
                    <div className="p-2.5 bg-slate-50 border-l-4 border-slate-700 text-slate-800 rounded-r flex items-start gap-2">
                      <span className="font-bold">3. Endpoint Isolation:</span>
                      <span>If macro or script execution occurred, isolate affected host and initiate forensic triage.</span>
                    </div>
                  </>
                ) : data.verdict === 'SUSPICIOUS' ? (
                  <>
                    <div className="p-2.5 bg-amber-50 border-l-4 border-amber-500 text-amber-900 rounded-r flex items-start gap-2">
                      <span className="font-bold">1. Caution Advised:</span>
                      <span>Do not enter confidential credentials or execute macros. Confirm sender authenticity through out-of-band channels.</span>
                    </div>
                    <div className="p-2.5 bg-slate-50 border-l-4 border-slate-700 text-slate-800 rounded-r flex items-start gap-2">
                      <span className="font-bold">2. Sandbox Testing:</span>
                      <span>Verify suspicious links and attachments inside an isolated security sandbox before dissemination.</span>
                    </div>
                  </>
                ) : (
                  <div className="p-2.5 bg-emerald-50 border-l-4 border-emerald-600 text-emerald-900 rounded-r flex items-start gap-2">
                    <span className="font-bold">Standard Practice:</span>
                    <span>No active threat indicators detected. Continue standard cybersecurity hygiene and email verification.</span>
                  </div>
                )}
              </div>
            </div>

            {/* Official Report Footer & Certification Block */}
            <div className="border-t-2 border-slate-900 pt-6 mt-8 text-[10px] text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-4">
              <div>
                <p className="font-bold text-slate-800 uppercase tracking-wider">
                  DARKHOOK DEFENSE AUTONOMOUS THREAT INTELLIGENCE
                </p>
                <p>Generated automatically by multi-modal machine learning & heuristic security rule engines.</p>
              </div>

              <div className="text-right shrink-0">
                <p className="font-mono font-bold text-slate-700">VERIFIED REPORT CERTIFICATE</p>
                <p>System Timestamp: {new Date().toUTCString()}</p>
              </div>
            </div>

          </div>
        </div>

      </div>
    </div>
  );
}
