import { Navbar } from '../components/Navbar';
import { HeroSection } from '../components/HeroSection';
import { AboutSection } from '../components/AboutSection';
import { ThreeLayersSection } from '../components/ThreeLayersSection';
import { HowItWorksSection } from '../components/HowItWorksSection';
import { ScanDemoSection } from '../components/ScanDemoSection';
import { ThreatStatsSection } from '../components/ThreatStatsSection';
import { RiskScoreSection } from '../components/RiskScoreSection';
import { ComparisonSection } from '../components/ComparisonSection';
import { TeamSection } from '../components/TeamSection';
import { FAQSection } from '../components/FAQSection';
import { Footer } from '../components/Footer';

export default function Home() {
  return (
    <div className="min-h-screen bg-[#2D3250]">
      <Navbar />
      <HeroSection />
      <AboutSection />
      <ThreeLayersSection />
      <HowItWorksSection />
      <ScanDemoSection />
      <ThreatStatsSection />
      <RiskScoreSection />
      <ComparisonSection />
      <TeamSection />
      <FAQSection />
      <Footer />
    </div>
  );
}
