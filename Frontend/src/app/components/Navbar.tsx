import { Shield, Menu, X, LayoutDashboard, LogIn } from 'lucide-react';
import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { useNavigate, Link } from 'react-router';
import { useAuth } from '../contexts/AuthContext';
import logo from '../../assets/eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png';

export function Navbar() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
      setMobileMenuOpen(false);
    }
  };

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 h-[68px] bg-[#0D1F38]/95 backdrop-blur-xl border-b border-[#1E3A5F]">
      <div className="max-w-[1440px] mx-auto px-4 h-full flex items-center justify-between">
        {/* Logo */}
        <div className="flex items-center gap-2 cursor-pointer" onClick={() => scrollToSection('hero')}>
          <img src={logo} alt="Darkhook Defense" className="h-14" />
        </div>

        {/* Desktop Nav */}
        <div className="hidden md:flex items-center gap-8">
          <button
            onClick={() => scrollToSection('hero')}
            className="text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
          >
            Home
          </button>
          <button
            onClick={() => scrollToSection('about')}
            className="text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
          >
            About
          </button>
          
          <button
            onClick={() => scrollToSection('team')}
            className="text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
          >
            Team
          </button>
          {isAuthenticated ? (
            <Link
              to="/dashboard"
              className="px-6 py-2 bg-[#00C2FF] text-[#060D1A] rounded-[10px] font-semibold hover:bg-[#00A8E0] transition-all shadow-[0_0_24px_rgba(0,194,255,0.35)] flex items-center gap-2"
            >
              <LayoutDashboard className="w-4 h-4" />
              Dashboard
            </Link>
          ) : (
            <Link
              to="/login"
              className="px-6 py-2 bg-[#00C2FF] text-[#060D1A] rounded-[10px] font-semibold hover:bg-[#00A8E0] transition-all shadow-[0_0_24px_rgba(0,194,255,0.35)] flex items-center gap-2"
            >
              <LogIn className="w-4 h-4" />
              Login
            </Link>
          )}
        </div>

        {/* Mobile Menu Button */}
        <button
          className="md:hidden text-white"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
        >
          {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
      </div>

      {/* Mobile Menu */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="md:hidden bg-[#0D1F38] border-b border-[#1E3A5F]"
          >
            <div className="flex flex-col p-6 gap-4">
              <button
                onClick={() => scrollToSection('hero')}
                className="text-left text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
              >
                Home
              </button>
              <button
                onClick={() => scrollToSection('about')}
                className="text-left text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
              >
                About
              </button>
              <button
                onClick={() => scrollToSection('how-it-works')}
                className="text-left text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
              >
                How It Works
              </button>
              <button
                onClick={() => scrollToSection('team')}
                className="text-left text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
              >
                Team
              </button>
              {isAuthenticated ? (
                <Link
                  to="/dashboard"
                  className="flex items-center gap-2 px-6 py-2 bg-[#00C2FF] text-[#060D1A] rounded-[10px] font-semibold hover:bg-[#00A8E0] transition-all text-center justify-center"
                >
                  <LayoutDashboard className="w-4 h-4" />
                  Dashboard
                </Link>
              ) : (
                <Link
                  to="/login"
                  className="flex items-center gap-2 px-6 py-2 bg-[#00C2FF] text-[#060D1A] rounded-[10px] font-semibold hover:bg-[#00A8E0] transition-all text-center justify-center"
                >
                  <LogIn className="w-4 h-4" />
                  Login
                </Link>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </nav>
  );
}