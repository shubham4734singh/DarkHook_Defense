import { motion, AnimatePresence } from 'motion/react';
import { useState, useEffect } from 'react';
import { Link2, Mail, FileText, Loader2 } from 'lucide-react';

type ScanType = 'url' | 'email' | 'document';
type WidgetState = 'input' | 'scanning' | 'result';

interface ScanResult {
  score: number;
  verdict: 'safe' | 'suspicious' | 'phishing';
  duration: number;
  flags: Array<{
    name: string;
    severity: 'high' | 'medium' | 'low';
  }>;
}

const scanMessages = [
  'Extracting 20 URL features...',
  'Checking typosquatting patterns...',
  'Running ML model...',
  'Scoring threat level...'
];

export function HeroScanWidget() {
  const [activeTab, setActiveTab] = useState<ScanType>('url');
  const [inputValue, setInputValue] = useState('');
  const [widgetState, setWidgetState] = useState<WidgetState>('input');
  const [scanProgress, setScanProgress] = useState(0);
  const [messageIndex, setMessageIndex] = useState(0);
  const [elapsedTime, setElapsedTime] = useState(0);
  const [result, setResult] = useState<ScanResult | null>(null);

  // Pulse animation for scan button
  const pulseAnimation = {
    boxShadow: [
      '0 0 0 0 rgba(169, 203, 224, 0.4)',
      '0 0 0 8px rgba(169, 203, 224, 0)',
    ]
  };

  // Simulate scanning process
  useEffect(() => {
    if (widgetState === 'scanning') {
      // Progress animation
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
          if (prev < 85) return prev + 5;
          return prev;
        });
      }, 100);

      // Message rotation
      const messageInterval = setInterval(() => {
        setMessageIndex(prev => (prev + 1) % scanMessages.length);
      }, 800);

      // Timer
      const timerInterval = setInterval(() => {
        setElapsedTime(prev => prev + 1);
      }, 100);

      // Complete scan after 2 seconds
      const completionTimeout = setTimeout(() => {
        // Generate mock result
        const mockScore = Math.floor(Math.random() * 100);
        let verdict: 'safe' | 'suspicious' | 'phishing' = 'safe';
        if (mockScore >= 70) verdict = 'phishing';
        else if (mockScore >= 40) verdict = 'suspicious';

        setResult({
          score: mockScore,
          verdict,
          duration: elapsedTime / 10,
          flags: [
            { name: 'IP Address in URL', severity: 'high' },
            { name: 'Suspicious TLD (.xyz)', severity: 'medium' },
            { name: 'Missing HTTPS', severity: 'high' },
            { name: 'Shortened URL detected', severity: 'medium' },
            { name: 'Domain age < 30 days', severity: 'high' }
          ]
        });
        setWidgetState('result');
      }, 2000);

      return () => {
        clearInterval(progressInterval);
        clearInterval(messageInterval);
        clearInterval(timerInterval);
        clearTimeout(completionTimeout);
      };
    }
  }, [widgetState, elapsedTime]);

  const handleScan = () => {
    if (!inputValue.trim()) return;
    setScanProgress(0);
    setMessageIndex(0);
    setElapsedTime(0);
    setWidgetState('scanning');
  };

  const handleReset = () => {
    setInputValue('');
    setWidgetState('input');
    setScanProgress(0);
    setResult(null);
    setElapsedTime(0);
  };

  const getPlaceholder = () => {
    switch (activeTab) {
      case 'url': return 'Enter URL to scan (e.g., https://example.com)';
      case 'email': return 'Paste email content or upload .eml file';
      case 'document': return 'Upload document (PDF, DOCX, XLSX, PPTX)';
    }
  };

  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case 'safe': return '#10B981';
      case 'suspicious': return '#F59E0B';
      case 'phishing': return '#EF4444';
      default: return '#668CA9';
    }
  };

  const getVerdictLabel = (verdict: string) => {
    switch (verdict) {
      case 'safe': return '🟢 SAFE';
      case 'suspicious': return '🟡 SUSPICIOUS';
      case 'phishing': return '🔴 PHISHING';
      default: return '';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high': return '#EF4444';
      case 'medium': return '#F59E0B';
      case 'low': return '#10B981';
      default: return '#668CA9';
    }
  };

  return (
    null
  );
}