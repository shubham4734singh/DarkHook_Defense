import { motion } from 'motion/react';
import { Mail, Lock, ArrowRight, Loader2 } from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../services/api';
import logo from '@/assets/164bd3b4c66bb15268339b22ae1165b91c7ea4e9.png';

export function Login() {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const [loading, setLoading] = useState(false);

  const [otpMode, setOtpMode] = useState(false);
  const [otp, setOtp] = useState('');
  const [otpLoading, setOtpLoading] = useState(false);
  const navigate = useNavigate();
  const { login, register } = useAuth();

  const startOtpFlow = async (targetEmail: string) => {
    setError('');
    setInfo('Sending OTP...');
    setOtp('');
    setOtpMode(true);

    try {
      const res = await api.requestEmailOtp(targetEmail);
      setInfo(res.message || 'OTP sent. Check your email.');
    } catch (err: any) {
      setInfo('');
      setError(err.message || 'Failed to send OTP. Please try again.');
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setInfo('');
    setOtpLoading(true);

    try {
      const res = await api.verifyEmailOtp(email, otp);
      setInfo(res.message || 'Email verified.');

      // After OTP verification, log the user in (works for both signup and login flows)
      await login(email, password);

      const redirectPath = localStorage.getItem('darkhook_redirect');
      if (redirectPath) {
        localStorage.removeItem('darkhook_redirect');
        navigate(redirectPath);
      } else {
        navigate('/scan/url');
      }
    } catch (err: any) {
      setError(err.message || 'OTP verification failed.');
    } finally {
      setOtpLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setInfo('');
    setLoading(true);
    
    try {
      if (isLogin) {
        // Call login from auth context (which now calls the API)
        await login(email, password);
      } else {
        // Call register from auth context
        await register(name, email, password);

        // After signup, start OTP verification step.
        await startOtpFlow(email);
        return;
      }
      
      // Check if there's a redirect path stored
      const redirectPath = localStorage.getItem('darkhook_redirect');
      if (redirectPath) {
        localStorage.removeItem('darkhook_redirect');
        navigate(redirectPath);
      } else {
        // Default to URL scan page
        navigate('/scan/url');
      }
    } catch (err: any) {
      const message = err.message || 'Authentication failed. Please try again.';

      // If backend blocks login until verification, move user to OTP flow.
      if (typeof message === 'string' && message.toLowerCase().includes('email not verified')) {
        await startOtpFlow(email);
        setLoading(false);
        return;
      }

      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#060D1A] flex items-center justify-center px-4 py-16">
      {/* Background Effects */}
      <div className="absolute inset-0 opacity-[0.08]" style={{
        backgroundImage: `radial-gradient(circle, #1E3A5F 1px, transparent 1px)`,
        backgroundSize: '24px 24px'
      }} />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="relative z-10 w-full max-w-md"
      >
        {/* Card */}
        <div className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8 shadow-[0_0_40px_rgba(0,194,255,0.15)]">
          {/* Logo */}
          <div className="flex items-center justify-center mb-6">
            <img src={logo} alt="Darkhook Defense" className="h-20" />
          </div>

          {/* Title */}
          <h2 className="text-2xl font-bold text-white text-center mb-2">
            {otpMode ? 'Verify Your Email' : (isLogin ? 'Welcome Back' : 'Create Account')}
          </h2>
          <p className="text-[#8BA3BC] text-center mb-6">
            {otpMode
              ? 'Enter the 6-digit code to continue'
              : (isLogin ? 'Sign in to scan for threats' : 'Sign up to start protecting yourself')}
          </p>

          {/* Form */}
          {!otpMode ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              {!isLogin && (
                <div>
                  <label className="block text-white text-sm mb-2">Full Name</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="John Doe"
                    className="w-full px-4 py-3 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-white placeholder:text-[#8BA3BC] focus:border-[#00C2FF] focus:outline-none focus:ring-2 focus:ring-[#00C2FF]/40 transition-all"
                    required
                  />
                </div>
              )}

              <div>
                <label className="block text-white text-sm mb-2">Email Address</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[#8BA3BC]" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@example.com"
                    className="w-full pl-11 pr-4 py-3 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-white placeholder:text-[#8BA3BC] focus:border-[#00C2FF] focus:outline-none focus:ring-2 focus:ring-[#00C2FF]/40 transition-all"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-white text-sm mb-2">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[#8BA3BC]" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full pl-11 pr-4 py-3 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-white placeholder:text-[#8BA3BC] focus:border-[#00C2FF] focus:outline-none focus:ring-2 focus:ring-[#00C2FF]/40 transition-all"
                    required
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full px-6 py-3 bg-[#00C2FF] hover:bg-[#00A8E0] text-[#060D1A] font-semibold rounded-lg transition-all flex items-center justify-center gap-2 shadow-[0_0_24px_rgba(0,194,255,0.35)] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    {isLogin ? 'Signing In...' : 'Creating Account...'}
                  </>
                ) : (
                  <>
                    {isLogin ? 'Sign In' : 'Create Account'}
                    <ArrowRight className="w-5 h-5" />
                  </>
                )}
              </button>
            </form>
          ) : (
            <form onSubmit={handleVerifyOtp} className="space-y-4">
              <div className="text-[#8BA3BC] text-sm text-center">
                We sent a verification code to <span className="text-white">{email || 'your email'}</span>.
              </div>
              <div>
                <label className="block text-white text-sm mb-2">Email Address</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[#8BA3BC]" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full pl-11 pr-4 py-3 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-white placeholder:text-[#8BA3BC] focus:border-[#00C2FF] focus:outline-none focus:ring-2 focus:ring-[#00C2FF]/40 transition-all"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-white text-sm mb-2">OTP Code</label>
                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value)}
                  placeholder="Enter 6-digit code"
                  className="w-full px-4 py-3 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-white placeholder:text-[#8BA3BC] focus:border-[#00C2FF] focus:outline-none focus:ring-2 focus:ring-[#00C2FF]/40 transition-all"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={otpLoading}
                className="w-full px-6 py-3 bg-[#00C2FF] hover:bg-[#00A8E0] text-[#060D1A] font-semibold rounded-lg transition-all flex items-center justify-center gap-2 shadow-[0_0_24px_rgba(0,194,255,0.35)] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {otpLoading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Verifying...
                  </>
                ) : (
                  <>
                    Verify OTP
                    <ArrowRight className="w-5 h-5" />
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={() => startOtpFlow(email)}
                disabled={otpLoading}
                className="w-full px-6 py-3 bg-transparent border border-[#1E3A5F] hover:border-[#00C2FF] text-white font-semibold rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Resend OTP
              </button>

              <button
                type="button"
                onClick={() => {
                  setOtpMode(false);
                  setOtp('');
                  setInfo('');
                  setError('');
                }}
                disabled={otpLoading}
                className="w-full text-[#8BA3BC] hover:text-[#00C2FF] text-sm transition-colors"
              >
                ← Back
              </button>
            </form>
          )}

          {/* Info Message */}
          {info && (
            <div className="mt-4 p-3 bg-[#00C2FF]/10 border border-[#00C2FF]/40 rounded-lg text-[#8BA3BC] text-sm text-center">
              {info}
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="mt-4 p-3 bg-red-500/20 border border-red-500 rounded-lg text-red-400 text-sm text-center">
              {error}
            </div>
          )}

          {/* Toggle */}
          {!otpMode && (
            <div className="mt-6 text-center">
              <button
                onClick={() => setIsLogin(!isLogin)}
                className="text-[#8BA3BC] hover:text-[#00C2FF] text-sm transition-colors"
              >
                {isLogin ? "Don't have an account? " : "Already have an account? "}
                <span className="text-[#00C2FF] font-semibold">
                  {isLogin ? 'Sign Up' : 'Sign In'}
                </span>
              </button>
            </div>
          )}

          {/* Back to Home */}
          <div className="mt-6 text-center">
            <Link to="/" className="text-[#8BA3BC] hover:text-[#00C2FF] text-sm transition-colors">
              ← Back to Home
            </Link>
          </div>
        </div>
      </motion.div>
    </div>
  );
}