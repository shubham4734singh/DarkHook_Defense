import { motion } from 'motion/react';
import { Zap, Play, LayoutDashboard } from 'lucide-react';
import { Link } from 'react-router';
import { ScanNowDropdown } from './ScanNowDropdown';
import { HeroScanWidget } from './HeroScanWidget';
import { useAuth } from '../contexts/AuthContext';

export function HeroSection() {
  const { isAuthenticated } = useAuth();

  return (
    <section id="hero" className="relative min-h-screen bg-[#060D1A] flex items-center justify-center overflow-hidden pt-[68px]">
      {/* Dot Grid Background */}
      <div className="absolute inset-0 opacity-[0.15]" style={{
        backgroundImage: `radial-gradient(circle, #1E3A5F 1px, transparent 1px)`,
        backgroundSize: '24px 24px'
      }} />

      {/* Floating Particles */}
      {[...Array(20)].map((_, i) => (
        <motion.div
          key={i}
          className="absolute w-2 h-2 bg-[#00C2FF] rounded-full opacity-30"
          initial={{ 
            x: Math.random() * window.innerWidth, 
            y: Math.random() * window.innerHeight,
            opacity: 0.3
          }}
          animate={{
            y: [null, Math.random() * window.innerHeight],
            x: [null, Math.random() * window.innerWidth],
          }}
          transition={{
            duration: 20 + Math.random() * 10,
            repeat: Infinity,
            ease: "linear"
          }}
        />
      ))}

      {/* Content */}
      <div className="relative z-10 max-w-[860px] mx-auto px-4 text-center">
        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="inline-flex items-center gap-2 px-4 py-2 bg-[#0D1F38] border border-[#00C2FF] rounded-full mb-6"
        >
          <Zap className="w-4 h-4 text-[#00C2FF]" />
          <span className="text-[#00C2FF] font-medium text-sm">Real-Time AI Phishing Detection</span>
        </motion.div>

        {/* Main Headline */}
        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-3xl sm:text-5xl md:text-6xl lg:text-7xl font-bold text-white mb-4"
          style={{ letterSpacing: '-1px' }}
        >
          Darkhook Defense
        </motion.h1>

        {/* Subheadline */}
        <motion.h2
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="text-xl sm:text-2xl md:text-3xl font-semibold text-[#00C2FF] mb-6"
        >
          We Hook Threats Before They Hook You.
        </motion.h2>

        {/* Description */}
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="text-[#8BA3BC] text-lg max-w-[580px] mx-auto mb-8 leading-relaxed"
        >
          AI-powered detection for Phishing URLs, Suspicious Emails, and Malicious Documents — all in one place, in under 3 seconds.
        </motion.p>

        {/* CTA Buttons */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-6"
        >
          {isAuthenticated ? (
            <Link
              to="/dashboard"
              className="px-8 py-3 bg-[#00C2FF] text-[#060D1A] rounded-[10px] font-semibold hover:bg-[#00A8E0] transition-all shadow-[0_0_24px_rgba(0,194,255,0.35)] flex items-center gap-2"
            >
              <LayoutDashboard className="w-5 h-5" />
              Go to Dashboard
            </Link>
          ) : (
            <ScanNowDropdown />
          )}
          <button
            onClick={() => document.getElementById('how-it-works')?.scrollIntoView({ behavior: 'smooth' })}
            className="px-8 py-3 border-2 border-[#00C2FF] text-[#00C2FF] rounded-[10px] font-semibold hover:bg-[#00C2FF]/10 transition-all flex items-center gap-2"
          >
            <Play className="w-5 h-5" />
            See How It Works
          </button>
        </motion.div>

        {/* Trust Bar */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="flex flex-wrap items-center justify-center gap-4 text-[#8BA3BC] text-sm mb-12"
        >
          
          
          <span className="flex items-center gap-1">
            <Zap className="w-4 h-4" />
            Results in &lt; 3 Seconds
          </span>
          <span>•</span>
          <span>🎓 Built by Students</span>
        </motion.div>

        {/* Hero Scan Widget */}
        <HeroScanWidget />
      </div>
    </section>
  );
}