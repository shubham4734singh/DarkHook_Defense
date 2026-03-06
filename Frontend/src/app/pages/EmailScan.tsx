import { motion } from 'motion/react';
import { Shield, Mail, Upload, AlertTriangle, CheckCircle, XCircle, ArrowLeft, LogOut } from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { useAuth } from '../contexts/AuthContext';
import logo from '@/assets/eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png';

export function EmailScan() {
  const [emailContent, setEmailContent] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<any>(null);
  const navigate = useNavigate();
  const { logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const handleScan = () => {
    setScanning(true);
    
    // Mock scanning process
    setTimeout(() => {
      setResult({
        riskScore: Math.floor(Math.random() * 100),
        status: ['safe', 'suspicious', 'dangerous'][Math.floor(Math.random() * 3)],
        threats: [
          { name: 'Sender Verification', status: Math.random() > 0.5 ? 'safe' : 'warning' },
          { name: 'Suspicious Links', status: 'safe' },
          { name: 'Phishing Keywords', status: Math.random() > 0.5 ? 'safe' : 'warning' },
          { name: 'Attachment Safety', status: 'safe' },
          { name: 'Email Header Analysis', status: 'safe' },
        ]
      });
      setScanning(false);
    }, 2000);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        setEmailContent(event.target?.result as string);
      };
      reader.readAsText(file);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'safe': return '#00D68F';
      case 'suspicious': return '#FFAA00';
      case 'dangerous': return '#FF3B3B';
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
              disabled={!emailContent || scanning}
              className="w-full px-6 py-3 bg-[#00C2FF] hover:bg-[#00A8E0] text-[#060D1A] font-semibold rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_24px_rgba(0,194,255,0.35)]"
            >
              {scanning ? 'Scanning...' : 'Scan Email'}
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
                    style={{ borderColor: getStatusColor(result.status) }}>
                    <span className="text-4xl font-bold text-white">{result.riskScore}</span>
                  </div>
                  <h3 className="text-2xl font-bold mb-2" style={{ color: getStatusColor(result.status) }}>
                    {result.status === 'safe' ? '🟢 SAFE' : result.status === 'suspicious' ? '🟡 SUSPICIOUS' : '🔴 DANGEROUS'}
                  </h3>
                  <p className="text-[#8BA3BC]">
                    {result.status === 'safe' ? 'No threats detected' : result.status === 'suspicious' ? 'Proceed with caution' : 'Do not trust this email'}
                  </p>
                </div>
              </div>

              {/* Threat Details */}
              <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8">
                <h3 className="text-xl font-bold text-white mb-4">Email Analysis</h3>
                <div className="space-y-3">
                  {result.threats.map((threat: any, index: number) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-4 bg-[#060D1A] border border-[#1E3A5F] rounded-lg"
                    >
                      <span className="text-white font-medium">{threat.name}</span>
                      <div className="flex items-center gap-2" style={{ color: getStatusColor(threat.status) }}>
                        {getStatusIcon(threat.status)}
                        <span className="text-sm font-semibold uppercase">{threat.status}</span>
                      </div>
                    </div>
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