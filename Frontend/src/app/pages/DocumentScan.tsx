import { motion } from 'motion/react';
import { Shield, FileText, Upload, AlertTriangle, CheckCircle, XCircle, ArrowLeft, LogOut } from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { useAuth } from '../contexts/AuthContext';
import logo from '@/assets/eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

interface Finding {
  name: string;
  severity: string;
}

interface ScoreBreakdownItem {
  finding_type: string;
  score: number;
}

interface ScanResult {
  fileName: string;
  fileSize: string;
  fileHash: string;
  riskScore: number;
  verdict: string;
  scanTime: number;
  totalFindings: number;
  findings: string[];
  scoreBreakdown: ScoreBreakdownItem[];
  details: string[];
}

export function DocumentScan() {
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
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
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await fetch(`${API_BASE_URL}/scan/document`, {
        method: 'POST',
        body: formData,
      });
      
      if (!response.ok) {
        throw new Error('Failed to scan document');
      }
      
      const data: ScanResult = await response.json();
      setResult(data);
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
    }
  };

  const getVerdictColor = (verdict: string) => {
    if (verdict.includes('Safe')) return '#00D68F';
    if (verdict.includes('Suspicious')) return '#FFAA00';
    if (verdict.includes('High Risk')) return '#FF6633';
    if (verdict.includes('Dangerous')) return '#FF3B3B';
    return '#1E3A5F';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'safe': return '#00D68F';
      case 'warning': return '#FFAA00';
      case 'danger': return '#FF6633';
      case 'critical': return '#FF3B3B';
      default: return '#1E3A5F';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
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
          <Link to="/" className="flex items-center gap-2 cursor-pointer">
            <img src={logo} alt="Darkhook Defense" className="h-14" />
          </Link>

          {/* Nav Items */}
          <div className="flex items-center gap-6">
            <Link
              to="/"
              className="flex items-center gap-2 text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span className="hidden sm:inline">Back to Home</span>
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
                <FileText className="w-6 h-6 text-[#00C2FF]" />
              </div>
              <div>
                <h1 className="text-3xl font-bold text-white">Document Scanner</h1>
                <p className="text-[#8BA3BC]">Scan documents for malicious content and macros</p>
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
                Upload document (PDF, DOCX, XLSX, PPTX)
              </label>
              <div className="relative">
                <input
                  type="file"
                  accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx"
                  onChange={handleFileUpload}
                  className="hidden"
                  id="document-upload"
                />
                <label
                  htmlFor="document-upload"
                  className="flex flex-col items-center justify-center gap-3 px-6 py-12 bg-[#060D1A] border-2 border-dashed border-[#1E3A5F] rounded-lg cursor-pointer hover:border-[#00C2FF] transition-all"
                >
                  <Upload className="w-8 h-8 text-[#00C2FF]" />
                  <div className="text-center">
                    <p className="text-white font-medium mb-1">
                      {file ? file.name : 'Click to upload document'}
                    </p>
                    <p className="text-[#8BA3BC] text-sm">
                      PDF, DOCX, XLSX, PPTX up to 10MB
                    </p>
                  </div>
                </label>
              </div>
            </div>

            {file && (
              <div className="mb-6 p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <FileText className="w-5 h-5 text-[#00C2FF]" />
                    <div>
                      <p className="text-white font-medium">{file.name}</p>
                      <p className="text-[#8BA3BC] text-sm">{(file.size / 1024).toFixed(2)} KB</p>
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      setFile(null);
                      setError(null);
                    }}
                    className="text-[#FF3B3B] hover:text-[#ff5555] text-sm font-medium"
                  >
                    Remove
                  </button>
                </div>
              </div>
            )}

            {error && (
              <div className="mb-6 p-4 bg-[#FF3B3B]/10 border border-[#FF3B3B] rounded-lg">
                <p className="text-[#FF3B3B] font-medium">{error}</p>
              </div>
            )}

            <button
              onClick={handleScan}
              disabled={!file || scanning}
              className="w-full px-6 py-3 bg-[#00C2FF] hover:bg-[#00A8E0] text-[#060D1A] font-semibold rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_24px_rgba(0,194,255,0.35)]"
            >
              {scanning ? 'Scanning...' : 'Scan Document'}
            </button>
          </motion.div>

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
                  <div className="inline-flex items-center justify-center w-32 h-32 rounded-full border-8 mb-4"
                    style={{ borderColor: getVerdictColor(result.verdict) }}>
                    <span className="text-4xl font-bold text-white">{result.riskScore}</span>
                  </div>
                  <h3 className="text-2xl font-bold mb-2" style={{ color: getVerdictColor(result.verdict) }}>
                    {result.riskScore < 30 ? '🟢 SAFE' : result.riskScore < 60 ? '🟡 SUSPICIOUS' : result.riskScore < 80 ? '🟠 HIGH RISK' : '🔴 CRITICAL'}
                  </h3>
                  <p className="text-[#8BA3BC]">
                    {result.verdict}
                  </p>
                </div>

                <div className="mt-6 pt-6 border-t border-[#1E3A5F]">
                  <div className="grid grid-cols-2 gap-4 text-center">
                    <div>
                      <p className="text-[#8BA3BC] text-sm mb-1">File Name</p>
                      <p className="text-white font-medium text-sm truncate">{result.fileName}</p>
                    </div>
                    <div>
                      <p className="text-[#8BA3BC] text-sm mb-1">File Size</p>
                      <p className="text-white font-medium text-sm">{result.fileSize}</p>
                    </div>
                    <div>
                      <p className="text-[#8BA3BC] text-sm mb-1">Threats Found</p>
                      <p className="text-white font-medium text-sm">{result.totalFindings}</p>
                    </div>
                    <div>
                      <p className="text-[#8BA3BC] text-sm mb-1">Scan Time</p>
                      <p className="text-white font-medium text-sm">{result.scanTime.toFixed(2)}s</p>
                    </div>
                  </div>
                </div>

                <div className="mt-6 pt-6 border-t border-[#1E3A5F]">
                  <p className="text-[#8BA3BC] text-sm mb-2">File Hash (SHA256)</p>
                  <p className="text-white font-mono text-xs break-all bg-[#060D1A] p-3 rounded border border-[#1E3A5F]">{result.fileHash}</p>
                </div>
              </div>

              {/* Findings */}
              {result.totalFindings > 0 && (
                <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8">
                  <h3 className="text-xl font-bold text-white mb-4">Detected Threats ({result.totalFindings})</h3>
                  <div className="space-y-3">
                    {result.scoreBreakdown.map((item, index) => (
                      <div
                        key={index}
                        className="flex items-center justify-between p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg"
                      >
                        <span className="text-white font-medium">{item.finding_type}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-semibold text-white bg-[#1E3A5F] px-3 py-1 rounded">
                            +{item.score}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Detailed Analysis */}
              <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8">
                <h3 className="text-xl font-bold text-white mb-4">Detailed Analysis</h3>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {result.details.map((detail, index) => (
                    <p
                      key={index}
                      className="text-[#8BA3BC] text-sm font-mono"
                    >
                      {detail}
                    </p>
                  ))}
                </div>
              </div>
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
}