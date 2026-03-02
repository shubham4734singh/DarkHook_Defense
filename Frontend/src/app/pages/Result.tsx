import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Loader2, ArrowLeft, Save, ArrowRight, Clock, Zap } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router';
import { useAuth } from '../contexts/AuthContext';
import logo from '@/assets/eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png';

type Severity = 'high' | 'medium' | 'low';
type Verdict = 'safe' | 'suspicious' | 'phishing';

interface Flag {
  name: string;
  severity: Severity;
  explanation: string;
}

interface ScanResult {
  score: number;
  verdict: Verdict;
  scannedUrl: string;
  scanTime: string;
  duration: string;
  flags: Flag[];
}

// Mock results for different verdicts
const mockResults: Record<Verdict, ScanResult> = {
  safe: {
    score: 23,
    verdict: 'safe',
    scannedUrl: 'https://google.com/search?q=...',
    scanTime: '2 minutes ago',
    duration: '0.8s',
    flags: [
      {
        name: 'HTTP (No Encryption)',
        severity: 'low',
        explanation: 'Site served over HTTP without SSL. Low risk for read-only pages.'
      },
      {
        name: 'Subdomain Present',
        severity: 'low',
        explanation: 'URL contains a subdomain. Common in legitimate sites too.'
      }
    ]
  },
  suspicious: {
    score: 58,
    verdict: 'suspicious',
    scannedUrl: 'https://secure-login.tk/verify',
    scanTime: '1 minute ago',
    duration: '1.2s',
    flags: [
      {
        name: 'IP Address in URL',
        severity: 'high',
        explanation: 'Raw IP used instead of domain. Classic phishing technique.'
      },
      {
        name: 'Suspicious TLD (.xyz)',
        severity: 'high',
        explanation: '.xyz domains are heavily used in phishing campaigns.'
      },
      {
        name: 'Excessive Subdomains',
        severity: 'medium',
        explanation: '4 subdomain levels detected. Often used to mimic real domains.'
      },
      {
        name: 'No HTTPS',
        severity: 'medium',
        explanation: 'Login form found but connection is not encrypted.'
      },
      {
        name: 'Long URL (143 chars)',
        severity: 'low',
        explanation: 'Unusually long URLs can hide malicious redirects.'
      }
    ]
  },
  phishing: {
    score: 87,
    verdict: 'phishing',
    scannedUrl: 'http://paypa1.com/verify-account',
    scanTime: 'just now',
    duration: '1.5s',
    flags: [
      {
        name: 'IP Address in URL',
        severity: 'high',
        explanation: 'Raw IP used instead of domain. Classic phishing technique.'
      },
      {
        name: 'Typosquatting Detected',
        severity: 'high',
        explanation: 'Domain \'paypa1.com\' is 1 character from \'paypal.com\'. Levenshtein distance: 1.'
      },
      {
        name: 'Login Form on HTTP',
        severity: 'high',
        explanation: 'Password field detected on unencrypted connection.'
      },
      {
        name: 'Suspicious TLD (.tk)',
        severity: 'high',
        explanation: '.tk is a free TLD heavily exploited in phishing attacks.'
      },
      {
        name: 'Brand Name in Subdomain',
        severity: 'medium',
        explanation: '\'paypal\' appears in subdomain, not the actual domain. Deceptive.'
      },
      {
        name: 'Redirects Detected (3x)',
        severity: 'medium',
        explanation: 'URL redirects 3 times before reaching destination.'
      },
      {
        name: 'URL Entropy Score: 4.8',
        severity: 'low',
        explanation: 'High character randomness typical of generated phishing URLs.'
      }
    ]
  }
};

export function Result() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [isLoading, setIsLoading] = useState(true);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [dotCount, setDotCount] = useState(0);

  // Get verdict from URL params (for demo purposes)
  const verdictParam = searchParams.get('verdict') as Verdict || 'safe';

  useEffect(() => {
    // Simulate loading time
    const loadTime = Math.random() * 1700 + 800; // 0.8s to 2.5s
    const timer = setTimeout(() => {
      setResult(mockResults[verdictParam]);
      setIsLoading(false);
    }, loadTime);

    return () => clearTimeout(timer);
  }, [verdictParam]);

  // Animated dots for loading
  useEffect(() => {
    if (!isLoading) return;
    const interval = setInterval(() => {
      setDotCount(prev => (prev + 1) % 4);
    }, 400);
    return () => clearInterval(interval);
  }, [isLoading]);

  const getVerdictColor = (verdict: Verdict) => {
    switch (verdict) {
      case 'safe': return '#10B981';
      case 'suspicious': return '#F59E0B';
      case 'phishing': return '#EF4444';
    }
  };

  const getSeverityColor = (severity: Severity) => {
    switch (severity) {
      case 'high': return '#EF4444';
      case 'medium': return '#F59E0B';
      case 'low': return '#10B981';
    }
  };

  const getBannerGradient = (verdict: Verdict) => {
    switch (verdict) {
      case 'safe': return 'linear-gradient(135deg, #092C56 0%, #0a3d2e 100%)';
      case 'suspicious': return 'linear-gradient(135deg, #092C56 0%, #3d2e0a 100%)';
      case 'phishing': return 'linear-gradient(135deg, #092C56 0%, #3d0a0a 100%)';
    }
  };

  const getBannerText = (verdict: Verdict) => {
    switch (verdict) {
      case 'safe': return '✅ Scan Complete — No Threats Detected';
      case 'suspicious': return '⚠️ Scan Complete — Suspicious Content Found';
      case 'phishing': return '🚨 Scan Complete — Phishing Detected';
    }
  };

  const getVerdictBadge = (verdict: Verdict) => {
    switch (verdict) {
      case 'safe': return '🟢 SAFE';
      case 'suspicious': return '🟡 SUSPICIOUS';
      case 'phishing': return '🔴 PHISHING';
    }
  };

  return (
    <div className="min-h-screen" style={{ background: '#092C56' }}>
      {/* Navbar */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-[#060D1A] border-b border-[#1E3A5F]">
        <div className="max-w-[1200px] mx-auto px-4 h-[68px] flex items-center justify-between">
          <button
            onClick={() => navigate('/')}
            className="flex items-center gap-2 text-white hover:text-[#00C2FF] transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
            <span className="font-semibold">Back to Home</span>
          </button>
          <div className="flex items-center gap-4">
            <span className="text-[#8BA3BC] text-sm">
              {user?.name || user?.email}
            </span>
            <button
              onClick={logout}
              className="px-4 py-2 text-[#8BA3BC] hover:text-[#00C2FF] transition-colors text-sm"
            >
              Logout
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="pt-[100px] pb-16">
        <AnimatePresence mode="wait">
          {isLoading ? (
            <SkeletonLoader key="skeleton" dotCount={dotCount} />
          ) : result ? (
            <ResultContent key="result" result={result} navigate={navigate} />
          ) : null}
        </AnimatePresence>
      </div>
    </div>
  );
}

function SkeletonLoader({ dotCount }: { dotCount: number }) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.3 }}
    >
      {/* Scanning Banner */}
      <div
        className="w-full flex items-center justify-center"
        style={{
          background: 'linear-gradient(135deg, #225688 0%, #092C56 100%)',
          height: '56px'
        }}
      >
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
        >
          <Loader2 className="w-5 h-5 mr-3" style={{ color: '#A9CBE0' }} />
        </motion.div>
        <span
          style={{
            fontFamily: 'Raleway, sans-serif',
            fontSize: '16px',
            fontWeight: 600,
            color: '#A9CBE0'
          }}
        >
          Scanning... please wait{'.'.repeat(dotCount)}
        </span>
      </div>

      {/* Skeleton Content */}
      <div className="max-w-[1100px] mx-auto px-4 mt-10">
        <div className="grid md:grid-cols-2 gap-8">
          {/* Left Panel Skeleton */}
          <div
            style={{
              background: '#225688',
              border: '1px solid #668CA9',
              borderRadius: '16px',
              padding: '32px'
            }}
          >
            {/* Circle Placeholder */}
            <div className="flex justify-center mb-6">
              <div
                className="shimmer"
                style={{
                  width: '200px',
                  height: '200px',
                  borderRadius: '50%'
                }}
              />
            </div>

            {/* Verdict Badge Placeholder */}
            <div className="flex justify-center mb-5">
              <div
                className="shimmer"
                style={{
                  width: '140px',
                  height: '32px',
                  borderRadius: '999px'
                }}
              />
            </div>

            {/* Scanned Item Placeholder */}
            <div
              className="shimmer mb-5"
              style={{
                width: '100%',
                height: '48px',
                borderRadius: '10px'
              }}
            />

            {/* Button Placeholders */}
            <div className="space-y-2.5">
              <div
                className="shimmer"
                style={{
                  width: '100%',
                  height: '44px',
                  borderRadius: '10px'
                }}
              />
              <div
                className="shimmer"
                style={{
                  width: '100%',
                  height: '44px',
                  borderRadius: '10px'
                }}
              />
            </div>
          </div>

          {/* Right Panel Skeleton */}
          <div
            style={{
              background: '#225688',
              border: '1px solid #668CA9',
              borderRadius: '16px',
              padding: '32px'
            }}
          >
            {/* Title Placeholder */}
            <div
              className="shimmer mb-5"
              style={{
                width: '160px',
                height: '20px',
                borderRadius: '4px'
              }}
            />

            {/* Flag Card Placeholders */}
            <div className="space-y-3">
              {[1, 2, 3, 4].map((i) => (
                <div
                  key={i}
                  className="shimmer"
                  style={{
                    width: '100%',
                    height: '72px',
                    borderRadius: '10px'
                  }}
                />
              ))}
            </div>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes shimmer {
          0% {
            background-position: 200% 0;
          }
          100% {
            background-position: -200% 0;
          }
        }

        .shimmer {
          background: linear-gradient(90deg, 
            #225688 0%, 
            #2d6a9e 50%, 
            #225688 100%);
          background-size: 200% 100%;
          animation: shimmer 1.5s infinite linear;
        }
      `}</style>
    </motion.div>
  );
}

function ResultContent({ result, navigate }: { result: ScanResult; navigate: any }) {
  const verdictColor = result.verdict === 'safe' ? '#10B981' : result.verdict === 'suspicious' ? '#F59E0B' : '#EF4444';
  const circumference = 2 * Math.PI * 94; // radius 94px for 200px circle with stroke 12
  const strokeDashoffset = circumference - (result.score / 100) * circumference;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.3 }}
    >
      {/* Result Banner */}
      <motion.div
        className="w-full flex items-center justify-center"
        style={{
          background: result.verdict === 'safe' 
            ? 'linear-gradient(135deg, #092C56 0%, #0a3d2e 100%)'
            : result.verdict === 'suspicious'
            ? 'linear-gradient(135deg, #092C56 0%, #3d2e0a 100%)'
            : 'linear-gradient(135deg, #092C56 0%, #3d0a0a 100%)',
          height: '56px',
          borderBottom: `1px solid ${verdictColor}`,
          borderBottomWidth: '1px',
          opacity: 0.3
        }}
        animate={result.verdict === 'phishing' ? {
          borderBottomWidth: ['1px', '2px', '1px']
        } : {}}
        transition={result.verdict === 'phishing' ? {
          duration: 1,
          repeat: Infinity
        } : {}}
      >
        <span
          style={{
            fontFamily: 'Raleway, sans-serif',
            fontSize: '16px',
            fontWeight: 600,
            color: verdictColor
          }}
        >
          {result.verdict === 'safe' && '✅ Scan Complete — No Threats Detected'}
          {result.verdict === 'suspicious' && '⚠️ Scan Complete — Suspicious Content Found'}
          {result.verdict === 'phishing' && '🚨 Scan Complete — Phishing Detected'}
        </span>
      </motion.div>

      {/* Two Column Layout */}
      <div className="max-w-[1100px] mx-auto px-4 mt-10">
        <div className="grid md:grid-cols-2 gap-8">
          {/* Left Panel */}
          <div
            style={{
              background: '#225688',
              border: '1px solid #668CA9',
              borderRadius: '16px',
              padding: '32px'
            }}
          >
            {/* Circular Score Meter */}
            <div className="flex justify-center mb-6 relative">
              <svg width="200" height="200" className="transform -rotate-90">
                {/* Track ring */}
                <circle
                  cx="100"
                  cy="100"
                  r="94"
                  fill="none"
                  stroke="#092C56"
                  strokeWidth="12"
                />
                {/* Fill arc */}
                <motion.circle
                  cx="100"
                  cy="100"
                  r="94"
                  fill="none"
                  stroke={verdictColor}
                  strokeWidth="12"
                  strokeLinecap="round"
                  initial={{ strokeDasharray: circumference, strokeDashoffset: circumference }}
                  animate={{ strokeDashoffset }}
                  transition={{ duration: 1.2, ease: 'easeOut' }}
                  style={{ strokeDasharray: circumference }}
                />
              </svg>
              <div 
                className="absolute inset-0 flex flex-col items-center justify-center"
                style={{
                  boxShadow: result.verdict === 'phishing' 
                    ? '0 0 32px rgba(239,68,68,0.25)' 
                    : result.verdict === 'suspicious'
                    ? '0 0 32px rgba(245,158,11,0.2)'
                    : '0 0 32px rgba(16,185,129,0.2)',
                  borderRadius: '50%',
                  width: '200px',
                  height: '200px'
                }}
              >
                <span
                  style={{
                    fontFamily: 'Raleway, sans-serif',
                    fontSize: '48px',
                    fontWeight: 700,
                    color: '#F0F5F4'
                  }}
                >
                  {result.score}
                </span>
                <span
                  style={{
                    fontFamily: 'Raleway, sans-serif',
                    fontSize: '18px',
                    color: '#668CA9'
                  }}
                >
                  / 100
                </span>
              </div>
            </div>

            {/* Verdict Badge */}
            <div className="flex justify-center mb-5">
              <motion.div
                style={{
                  background: result.verdict === 'safe' 
                    ? 'rgba(16,185,129,0.12)'
                    : result.verdict === 'suspicious'
                    ? 'rgba(245,158,11,0.12)'
                    : 'rgba(239,68,68,0.15)',
                  border: `1px solid ${verdictColor}`,
                  color: verdictColor,
                  fontFamily: 'Raleway, sans-serif',
                  fontSize: '15px',
                  fontWeight: 600,
                  padding: '8px 24px',
                  borderRadius: '999px'
                }}
                animate={result.verdict === 'phishing' ? {
                  borderWidth: ['1px', '2px', '1px']
                } : {}}
                transition={result.verdict === 'phishing' ? {
                  duration: 1,
                  repeat: Infinity
                } : {}}
              >
                {getVerdictBadge(result.verdict)}
              </motion.div>
            </div>

            {/* Scanned Item */}
            <div
              className="mb-3"
              style={{
                background: '#092C56',
                border: '1px solid #668CA9',
                borderRadius: '8px',
                padding: '12px 16px'
              }}
            >
              <div
                className="mb-1"
                style={{
                  fontFamily: 'Raleway, sans-serif',
                  fontSize: '11px',
                  fontWeight: 500,
                  color: '#668CA9',
                  letterSpacing: '2px'
                }}
              >
                SCANNED URL
              </div>
              <div
                className="truncate"
                style={{
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '13px',
                  color: '#A9CBE0'
                }}
              >
                {result.scannedUrl}
              </div>
            </div>

            {/* Scan Meta */}
            <div
              className="flex items-center gap-2 mb-6 flex-wrap"
              style={{
                fontFamily: 'Raleway, sans-serif',
                fontSize: '13px',
                color: '#668CA9'
              }}
            >
              <span className="flex items-center gap-1">
                <Clock className="w-3.5 h-3.5" />
                Scanned {result.scanTime}
              </span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <Zap className="w-3.5 h-3.5" />
                Completed in {result.duration}
              </span>
            </div>

            {/* Buttons */}
            <div className="space-y-2.5">
              <button
                className="w-full py-3 rounded-lg font-semibold transition-all hover:opacity-90 flex items-center justify-center gap-2"
                style={{
                  background: '#A9CBE0',
                  color: '#092C56',
                  fontFamily: 'Raleway, sans-serif'
                }}
              >
                <Save className="w-4 h-4" />
                Save to History
              </button>
              <button
                onClick={() => navigate('/scan/url')}
                className="w-full py-3 rounded-lg font-semibold transition-all hover:bg-[#668CA9]/10 flex items-center justify-center gap-2"
                style={{
                  background: 'transparent',
                  border: '1px solid #668CA9',
                  color: '#A9CBE0',
                  fontFamily: 'Raleway, sans-serif'
                }}
              >
                <ArrowLeft className="w-4 h-4" />
                Scan Another
              </button>
            </div>
          </div>

          {/* Right Panel */}
          <div
            style={{
              background: '#225688',
              border: '1px solid #668CA9',
              borderRadius: '16px',
              padding: '32px'
            }}
          >
            {/* Panel Title Row */}
            <div className="flex items-center justify-between mb-5">
              <h3
                style={{
                  fontFamily: 'Raleway, sans-serif',
                  fontSize: '18px',
                  fontWeight: 600,
                  color: '#F0F5F4'
                }}
              >
                Detected Flags
              </h3>
              <div
                style={{
                  background: result.verdict === 'phishing' ? 'rgba(239,68,68,0.12)' : '#092C56',
                  border: `1px solid ${result.verdict === 'phishing' ? '#EF4444' : '#668CA9'}`,
                  color: result.verdict === 'phishing' ? '#EF4444' : '#668CA9',
                  fontFamily: 'Raleway, sans-serif',
                  fontSize: '13px',
                  padding: '4px 12px',
                  borderRadius: '999px'
                }}
              >
                {result.flags.length} flags
              </div>
            </div>

            {/* Flag Cards */}
            <div className="space-y-3 mb-5">
              {result.flags.map((flag, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: index * 0.05 }}
                  style={{
                    background: '#092C56',
                    border: '1px solid #668CA9',
                    borderRadius: '10px',
                    padding: '16px 20px'
                  }}
                >
                  <div className="flex items-start gap-3">
                    {/* Severity Dot */}
                    <div
                      className="mt-1.5"
                      style={{
                        width: '8px',
                        height: '8px',
                        borderRadius: '50%',
                        background: getSeverityColor(flag.severity),
                        flexShrink: 0
                      }}
                    />

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2 mb-1.5">
                        <h4
                          className="truncate"
                          style={{
                            fontFamily: 'Raleway, sans-serif',
                            fontSize: '15px',
                            fontWeight: 600,
                            color: '#F0F5F4'
                          }}
                        >
                          {flag.name}
                        </h4>
                        <div
                          className="flex-shrink-0"
                          style={{
                            background: flag.severity === 'high' 
                              ? 'rgba(239,68,68,0.12)'
                              : flag.severity === 'medium'
                              ? 'rgba(245,158,11,0.12)'
                              : 'rgba(16,185,129,0.12)',
                            border: `1px solid ${getSeverityColor(flag.severity)}`,
                            color: getSeverityColor(flag.severity),
                            fontFamily: 'Raleway, sans-serif',
                            fontSize: '11px',
                            fontWeight: 600,
                            padding: '2px 8px',
                            borderRadius: '999px'
                          }}
                        >
                          {flag.severity.toUpperCase()}
                        </div>
                      </div>
                      <p
                        style={{
                          fontFamily: 'Raleway, sans-serif',
                          fontSize: '13px',
                          color: '#A9CBE0',
                          lineHeight: '1.5'
                        }}
                      >
                        {flag.explanation}
                      </p>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>

            {/* Verdict-specific Card */}
            {result.verdict === 'safe' && (
              <div
                style={{
                  background: 'rgba(16,185,129,0.08)',
                  border: '1px solid rgba(16,185,129,0.3)',
                  borderRadius: '10px',
                  padding: '16px 20px'
                }}
              >
                <div className="flex gap-3">
                  <div className="text-xl">✅</div>
                  <div>
                    <p
                      className="mb-1"
                      style={{
                        fontFamily: 'Raleway, sans-serif',
                        fontSize: '15px',
                        fontWeight: 600,
                        color: '#10B981'
                      }}
                    >
                      This URL passed all major threat checks.
                    </p>
                    <p
                      style={{
                        fontFamily: 'Raleway, sans-serif',
                        fontSize: '13px',
                        color: '#A9CBE0'
                      }}
                    >
                      No phishing patterns, malicious scripts, or suspicious redirects found.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {result.verdict === 'suspicious' && (
              <div
                style={{
                  background: 'rgba(245,158,11,0.08)',
                  border: '1px solid rgba(245,158,11,0.3)',
                  borderRadius: '10px',
                  padding: '16px 20px'
                }}
              >
                <div className="flex gap-3">
                  <div className="text-xl">⚠️</div>
                  <div>
                    <p
                      className="mb-1"
                      style={{
                        fontFamily: 'Raleway, sans-serif',
                        fontSize: '15px',
                        fontWeight: 600,
                        color: '#F59E0B'
                      }}
                    >
                      Proceed with caution.
                    </p>
                    <p
                      style={{
                        fontFamily: 'Raleway, sans-serif',
                        fontSize: '13px',
                        color: '#A9CBE0'
                      }}
                    >
                      Multiple risk indicators detected. Verify this source before clicking.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {result.verdict === 'phishing' && (
              <div
                style={{
                  background: 'rgba(239,68,68,0.1)',
                  border: '1px solid rgba(239,68,68,0.4)',
                  borderRadius: '10px',
                  padding: '16px 20px'
                }}
              >
                <div className="flex gap-3">
                  <div className="text-xl">🚨</div>
                  <div>
                    <p
                      className="mb-1"
                      style={{
                        fontFamily: 'Raleway, sans-serif',
                        fontSize: '15px',
                        fontWeight: 700,
                        color: '#EF4444'
                      }}
                    >
                      Do NOT open this link.
                    </p>
                    <p
                      style={{
                        fontFamily: 'Raleway, sans-serif',
                        fontSize: '13px',
                        color: '#A9CBE0'
                      }}
                    >
                      High-confidence phishing detected. Close this tab and report the sender.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Module Chain Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="mt-8"
          style={{
            background: '#225688',
            border: '1px solid #668CA9',
            borderRadius: '16px',
            padding: '28px'
          }}
        >
          <h3
            className="mb-2"
            style={{
              fontFamily: 'Raleway, sans-serif',
              fontSize: '16px',
              fontWeight: 600,
              color: '#F0F5F4'
            }}
          >
            Module Chain
          </h3>
          <p
            className="mb-6"
            style={{
              fontFamily: 'Raleway, sans-serif',
              fontSize: '14px',
              color: '#668CA9'
            }}
          >
            Additional modules triggered during this scan.
          </p>

          {/* Flow Row */}
          <div className="flex flex-col md:flex-row items-center justify-center gap-3 flex-wrap">
            <div
              className="px-4 py-2 rounded-lg"
              style={{
                background: '#092C56',
                border: '1px solid #668CA9',
                color: '#F0F5F4',
                fontFamily: 'Raleway, sans-serif',
                fontSize: '14px'
              }}
            >
              Scanned URL
            </div>
            <motion.div
              animate={{ x: [0, 5, 0] }}
              transition={{ duration: 1.5, repeat: Infinity }}
            >
              <ArrowRight className="w-5 h-5" style={{ color: '#A9CBE0' }} />
            </motion.div>
            <div
              className="px-4 py-2 rounded-lg flex items-center gap-2"
              style={{
                background: '#092C56',
                border: '1px solid #10B981',
                color: '#F0F5F4',
                fontFamily: 'Raleway, sans-serif',
                fontSize: '14px'
              }}
            >
              URL Shield ✓
            </div>
            <motion.div
              animate={{ x: [0, 5, 0] }}
              transition={{ duration: 1.5, repeat: Infinity, delay: 0.3 }}
            >
              <ArrowRight className="w-5 h-5" style={{ color: '#A9CBE0' }} />
            </motion.div>
            <div
              className="px-4 py-2 rounded-lg"
              style={{
                background: '#092C56',
                border: '1px solid #668CA9',
                color: '#F0F5F4',
                fontFamily: 'Raleway, sans-serif',
                fontSize: '14px'
              }}
            >
              No embedded links
            </div>
          </div>
        </motion.div>
      </div>
    </motion.div>
  );
}

function getVerdictBadge(verdict: Verdict) {
  switch (verdict) {
    case 'safe': return '🟢 SAFE';
    case 'suspicious': return '🟡 SUSPICIOUS';
    case 'phishing': return '🔴 PHISHING';
  }
}

function getSeverityColor(severity: Severity) {
  switch (severity) {
    case 'high': return '#EF4444';
    case 'medium': return '#F59E0B';
    case 'low': return '#10B981';
  }
}