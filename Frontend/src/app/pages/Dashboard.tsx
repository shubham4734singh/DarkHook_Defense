import { motion } from 'motion/react';
import { Link as LinkIcon, Mail, FileText, History, Zap, LogOut, ArrowLeft, ArrowRight, Shield } from 'lucide-react';
import { Link, useNavigate } from 'react-router';
import { useAuth } from '../contexts/AuthContext';
import logo from '@/assets/eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png';

const scanOptions = [
  {
    title: 'URL Scanner',
    description: 'Analyze URLs for phishing, typosquatting, and malicious patterns with ML-powered detection.',
    icon: LinkIcon,
    path: '/scan/url',
    color: '#00C2FF',
    gradient: 'from-[#00C2FF]/20 to-transparent',
  },
  {
    title: 'Email Scanner',
    description: 'Scan email files (.eml) for phishing indicators, suspicious headers, and malicious content.',
    icon: Mail,
    path: '/scan/email',
    color: '#A855F7',
    gradient: 'from-[#A855F7]/20 to-transparent',
  },
  {
    title: 'Document Scanner',
    description: 'Upload PDF, DOCX files to detect macros, embedded threats, and hidden malicious payloads.',
    icon: FileText,
    path: '/scan/document',
    color: '#F59E0B',
    gradient: 'from-[#F59E0B]/20 to-transparent',
  },
  {
    title: 'Scan History',
    description: 'View all your past scans, results, and threat analysis in one place.',
    icon: History,
    path: '/history',
    color: '#10B981',
    gradient: 'from-[#10B981]/20 to-transparent',
  },
];

export function Dashboard() {
  const navigate = useNavigate();
  const { logout, user } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <div className="min-h-screen bg-[#060D1A] relative overflow-hidden">
      {/* Dot Grid Background — same as HeroSection */}
      <div className="absolute inset-0 opacity-[0.15]" style={{
        backgroundImage: 'radial-gradient(circle, #1E3A5F 1px, transparent 1px)',
        backgroundSize: '24px 24px',
      }} />

      {/* Floating Particles */}
      {[...Array(15)].map((_, i) => (
        <motion.div
          key={i}
          className="absolute w-1.5 h-1.5 bg-[#00C2FF] rounded-full"
          style={{
            left: `${(i * 7 + 3) % 100}%`,
            top: `${(i * 13 + 5) % 100}%`,
          }}
          animate={{
            y: [0, -40, 0],
            opacity: [0.15, 0.4, 0.15],
          }}
          transition={{
            duration: 6 + i * 0.5,
            repeat: Infinity,
            ease: 'easeInOut',
          }}
        />
      ))}

      {/* Navbar */}
      <nav className="fixed top-0 left-0 right-0 z-50 h-[68px] bg-[#0D1F38]/95 backdrop-blur-xl border-b border-[#1E3A5F]">
        <div className="max-w-[1440px] mx-auto px-4 h-full flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2 cursor-pointer">
            <img src={logo} alt="Darkhook Defense" className="h-14" />
          </Link>

          <div className="flex items-center gap-6">
            <Link
              to="/"
              className="flex items-center gap-2 text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span className="hidden sm:inline">Home</span>
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

      {/* Hero-style Content */}
      <div className="relative z-10 pt-[68px] min-h-screen flex flex-col items-center">
        <div className="w-full max-w-[860px] mx-auto px-4 text-center pt-16 pb-6">
          {/* Badge — matches HeroSection */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="inline-flex items-center gap-2 px-4 py-2 bg-[#0D1F38] border border-[#00C2FF] rounded-full mb-6"
          >
            <Shield className="w-4 h-4 text-[#00C2FF]" />
            <span className="text-[#00C2FF] font-medium text-sm">Welcome to Your Dashboard</span>
          </motion.div>

          {/* Main Headline */}
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="text-4xl md:text-6xl font-bold text-white mb-4"
            style={{ letterSpacing: '-1px' }}
          >
            {user?.name ? `Hello, ${user.name}` : 'Your Security Hub'}
          </motion.h1>

          {/* Accent Subheadline */}
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="text-xl md:text-2xl font-semibold text-[#00C2FF] mb-4"
          >
            Hook Threats Before They Hook You.
          </motion.h2>

          {/* Description */}
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="text-[#8BA3BC] text-lg max-w-[580px] mx-auto mb-4 leading-relaxed"
          >
            Choose a scan module below to analyze URLs, emails, or documents for phishing threats — powered by AI.
          </motion.p>

          {/* Trust Bar — matches HeroSection */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.4 }}
            className="flex flex-wrap items-center justify-center gap-4 text-[#8BA3BC] text-sm mb-10"
          >
            <span className="flex items-center gap-1">
              <Zap className="w-4 h-4" />
              Results in &lt; 3 Seconds
            </span>
            <span>•</span>
            <span>3 Scan Modules</span>
            <span>•</span>
            <span>🛡️ AI-Powered Detection</span>
          </motion.div>
        </div>

        {/* Scan Cards */}
        <div className="w-full max-w-5xl mx-auto px-4 pb-16">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {scanOptions.map((option, index) => (
              <motion.div
                key={option.path}
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.4 + index * 0.1 }}
              >
                <Link
                  to={option.path}
                  className="group relative block bg-[#0D1F38]/80 backdrop-blur-sm border border-[#1E3A5F] rounded-2xl p-8 hover:border-[#00C2FF] transition-all duration-300 hover:shadow-[0_0_40px_rgba(0,194,255,0.15)] overflow-hidden"
                >
                  {/* Card glow on hover */}
                  <div
                    className={`absolute inset-0 bg-gradient-to-br ${option.gradient} opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-2xl`}
                  />

                  <div className="relative flex items-start gap-5">
                    <div
                      className="flex-shrink-0 w-14 h-14 rounded-xl flex items-center justify-center border transition-colors"
                      style={{
                        borderColor: `${option.color}40`,
                        backgroundColor: `${option.color}10`,
                      }}
                    >
                      <option.icon className="w-7 h-7" style={{ color: option.color }} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="text-xl font-bold text-white mb-2 group-hover:text-[#00C2FF] transition-colors flex items-center gap-2">
                        {option.title}
                        <ArrowRight className="w-4 h-4 opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all text-[#00C2FF]" />
                      </h3>
                      <p className="text-[#8BA3BC] text-sm leading-relaxed">
                        {option.description}
                      </p>
                    </div>
                  </div>
                </Link>
              </motion.div>
            ))}
          </div>
        </div>

        {/* Footer — matches landing page */}
        <div className="w-full border-t border-[#1E3A5F] mt-auto">
          <div className="max-w-[1200px] mx-auto px-4 py-8 flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-[#8BA3BC]">
            <p className="flex items-center gap-1">
              Built with ❤️ by Team Darkhook — CSE Minor Project 2026
            </p>
            <p>© 2026 Darkhook Defense. All rights reserved.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
