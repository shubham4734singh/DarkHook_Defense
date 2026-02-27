import { useState, useRef, useEffect } from 'react';
import { Link as LinkIcon, Mail, FileText, History, ChevronDown } from 'lucide-react';
import { useNavigate } from 'react-router';
import { useAuth } from '../contexts/AuthContext';
import { motion, AnimatePresence } from 'motion/react';

interface ScanNowDropdownProps {
  className?: string;
  variant?: 'primary' | 'secondary';
}

export function ScanNowDropdown({ className = '', variant = 'primary' }: ScanNowDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();

  const menuItems = [
    { label: 'URL Scanner', icon: LinkIcon, path: '/scan/url' },
    { label: 'Email Scanner', icon: Mail, path: '/scan/email' },
    { label: 'Document Scanner', icon: FileText, path: '/scan/document' },
    { label: 'Scan History', icon: History, path: '/history' },
  ];

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleItemClick = (path: string) => {
    setIsOpen(false);
    if (!isAuthenticated) {
      // Store the intended destination
      localStorage.setItem('darkhook_redirect', path);
      navigate('/login');
    } else {
      navigate(path);
    }
  };

  const baseButtonClasses = variant === 'primary'
    ? 'px-6 py-2 bg-[#00C2FF] text-[#060D1A] rounded-[10px] font-semibold hover:bg-[#00A8E0] transition-all shadow-[0_0_24px_rgba(0,194,255,0.35)]'
    : 'px-8 py-3 border-2 border-[#00C2FF] text-[#00C2FF] rounded-[10px] font-semibold hover:bg-[#00C2FF]/10 transition-all';

  return (
    <div className={`relative ${className}`} ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`${baseButtonClasses} flex items-center gap-2`}
      >
        Scan Now
        <ChevronDown className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
            className="absolute top-full mt-2 right-0 w-56 bg-[#0D1F38] border border-[#1E3A5F] rounded-lg shadow-[0_0_20px_rgba(0,0,0,0.5)] overflow-hidden z-50"
          >
            {menuItems.map((item, index) => (
              <button
                key={item.path}
                onClick={() => handleItemClick(item.path)}
                className={`w-full flex items-center gap-3 px-4 py-3 text-white hover:bg-[#00C2FF]/20 transition-colors text-left ${
                  index !== menuItems.length - 1 ? 'border-b border-[#1E3A5F]/30' : ''
                }`}
              >
                <item.icon className="w-5 h-5 text-[#00C2FF]" />
                <span className="text-sm font-medium">{item.label}</span>
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}