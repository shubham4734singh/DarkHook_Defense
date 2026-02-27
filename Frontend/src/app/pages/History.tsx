import { motion } from 'motion/react';
import { Shield, Link as LinkIcon, Mail, FileText, AlertTriangle, CheckCircle, Clock, ArrowLeft } from 'lucide-react';
import { Link, useNavigate } from 'react-router';
import { useAuth } from '../contexts/AuthContext';
import logo from '@/assets/eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png';

export function History() {
  const navigate = useNavigate();
  const { logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  // Mock scan history data
  const scanHistory = [
    {
      id: 1,
      type: 'url',
      content: 'https://suspicious-paypal.com/login',
      result: 'threat',
      score: 92,
      date: '2026-02-26 14:32',
      icon: LinkIcon,
    },
    {
      id: 2,
      type: 'email',
      content: 'Re: Your Account Has Been Locked',
      result: 'safe',
      score: 15,
      date: '2026-02-26 12:18',
      icon: Mail,
    },
    {
      id: 3,
      type: 'document',
      content: 'invoice_2024.pdf',
      result: 'warning',
      score: 58,
      date: '2026-02-25 18:45',
      icon: FileText,
    },
  ];

  return (
    <div className="min-h-screen bg-[#060D1A]">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-[#0D1F38]/95 backdrop-blur-xl border-b border-[#1E3A5F]">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2">
            <img src={logo} alt="Darkhook Defense" className="h-14" />
          </Link>
          <div className="flex items-center gap-4">
            <Link
              to="/"
              className="flex items-center gap-2 text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span className="hidden sm:inline">Back to Home</span>
            </Link>
            <button
              onClick={handleLogout}
              className="px-4 py-2 text-[#00C2FF] hover:bg-[#00C2FF]/10 rounded-lg transition-all"
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      {/* Background */}
      <div className="absolute inset-0 opacity-[0.08]" style={{
        backgroundImage: `radial-gradient(circle, #1E3A5F 1px, transparent 1px)`,
        backgroundSize: '24px 24px'
      }} />

      {/* Content */}
      <div className="relative z-10 max-w-6xl mx-auto px-4 py-12">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-4xl font-bold text-white mb-2">
            Scan <span className="text-[#00C2FF]">History</span>
          </h1>
          <p className="text-[#8BA3BC]">View your recent security scans and results</p>
        </motion.div>

        {/* History Grid */}
        <div className="grid gap-4">
          {scanHistory.length === 0 ? (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-12 text-center"
            >
              <Clock className="w-16 h-16 text-[#8BA3BC] mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-white mb-2">No scan history yet</h3>
              <p className="text-[#8BA3BC] mb-6">Your scans will appear here once you start using Darkhook Defense</p>
              <Link
                to="/"
                className="inline-flex items-center gap-2 px-6 py-3 bg-[#00C2FF] hover:bg-[#00A8E0] text-[#060D1A] font-semibold rounded-lg transition-all"
              >
                Start Scanning
              </Link>
            </motion.div>
          ) : (
            scanHistory.map((scan, index) => (
              <motion.div
                key={scan.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-6 hover:border-[#00C2FF] transition-all cursor-pointer"
              >
                <div className="flex items-center gap-6">
                  {/* Icon */}
                  <div className="flex-shrink-0">
                    <div className="w-12 h-12 bg-[#060D1A] border border-[#1E3A5F] rounded-xl flex items-center justify-center">
                      <scan.icon className="w-6 h-6 text-[#00C2FF]" />
                    </div>
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[#00C2FF] text-xs font-semibold uppercase tracking-wide">
                        {scan.type}
                      </span>
                      <span className="text-[#8BA3BC] text-xs">•</span>
                      <span className="text-[#8BA3BC] text-xs">{scan.date}</span>
                    </div>
                    <p className="text-white font-medium truncate mb-2">{scan.content}</p>
                  </div>

                  {/* Score */}
                  <div className="flex-shrink-0">
                    <div className={`px-4 py-2 rounded-lg ${
                      scan.result === 'safe'
                        ? 'bg-[#00D68F]/10 border border-[#00D68F]'
                        : scan.result === 'warning'
                        ? 'bg-[#FFAA00]/10 border border-[#FFAA00]'
                        : 'bg-[#FF3B3B]/10 border border-[#FF3B3B]'
                    }`}>
                      <div className="flex items-center gap-2">
                        {scan.result === 'safe' ? (
                          <CheckCircle className="w-5 h-5 text-[#00D68F]" />
                        ) : scan.result === 'warning' ? (
                          <AlertTriangle className="w-5 h-5 text-[#FFAA00]" />
                        ) : (
                          <AlertTriangle className="w-5 h-5 text-[#FF3B3B]" />
                        )}
                        <div>
                          <p className={`font-bold text-lg ${
                            scan.result === 'safe'
                              ? 'text-[#00D68F]'
                              : scan.result === 'warning'
                              ? 'text-[#FFAA00]'
                              : 'text-[#FF3B3B]'
                          }`}>
                            {scan.score}
                          </p>
                          <p className="text-[#8BA3BC] text-xs uppercase">{scan.result}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}