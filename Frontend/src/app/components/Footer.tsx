import { Shield, Heart } from 'lucide-react';

export function Footer() {
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <footer className="bg-[#060D1A] border-t border-[#1E3A5F] py-12">
      <div className="max-w-[1200px] mx-auto px-4">
        {/* Top Row */}
        <div className="flex flex-col md:flex-row items-center justify-between gap-8 mb-8 pb-8 border-b border-[#0D1F38]">
          {/* Left */}
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-6 h-6 text-[#00C2FF]" />
              <span className="font-bold text-white text-xl">Darkhook Defense</span>
            </div>
            <p className="text-[#8BA3BC] text-sm">
              We Hook Threats Before They Hook You.
            </p>
          </div>

          {/* Right - Nav Links */}
          <div className="flex flex-wrap items-center justify-center gap-6 text-sm">
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
              onClick={() => scrollToSection('scan-demo')}
              className="text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
            >
              Scan
            </button>
            <button
              onClick={() => scrollToSection('team')}
              className="text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
            >
              Team
            </button>
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
            >
              GitHub
            </a>
          </div>
        </div>

        {/* Bottom Row */}
        <div className="flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-[#8BA3BC]">
          <p className="flex items-center gap-1">
            Built with <Heart className="w-4 h-4 text-[#00C2FF]" /> by Team Darkhook — CSE Minor Project 2026
          </p>
          <p>
            © 2026 Darkhook Defense. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  );
}