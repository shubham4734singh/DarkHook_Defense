import { motion } from 'motion/react';
import { useEffect, useRef, useState } from 'react';
import { CheckCircle2, XCircle } from 'lucide-react';

function CountUpAnimation({ end, duration = 2 }: { end: number; duration?: number }) {
  const [count, setCount] = useState(0);
  const [hasAnimated, setHasAnimated] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !hasAnimated) {
          setHasAnimated(true);
          let startTime: number | null = null;
          const animate = (currentTime: number) => {
            if (!startTime) startTime = currentTime;
            const progress = Math.min((currentTime - startTime) / (duration * 1000), 1);
            setCount(Math.floor(progress * end));
            if (progress < 1) {
              requestAnimationFrame(animate);
            }
          };
          requestAnimationFrame(animate);
        }
      },
      { threshold: 0.5 }
    );

    if (ref.current) {
      observer.observe(ref.current);
    }

    return () => observer.disconnect();
  }, [end, duration, hasAnimated]);

  return <div ref={ref}>{count}</div>;
}

export function AboutSection() {
  return (
    <section id="about" className="bg-[#0D1F38] py-12 md:py-16">
      <div className="max-w-[1200px] mx-auto px-4">
        <div className="grid md:grid-cols-2 gap-12 items-center">
          {/* Left Column */}
          <div>
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6 }}
            >
              <p className="text-[#00C2FF] font-medium text-sm tracking-[3px] mb-4 uppercase">
                // About the Project
              </p>
              <h2 className="text-4xl md:text-5xl font-bold text-white mb-6 leading-tight">
                Built in the Dark.<br />Designed to Protect.
              </h2>
              <div className="space-y-4 text-[#ffffff99] text-base leading-relaxed">
                <p>
                  Every day, millions of phishing attacks slip past firewalls, spam filters, and human attention. One wrong click is all it takes.
                </p>
                <p>
                  Darkhook Defense is an AI-powered phishing detection engine built to catch what others miss — analyzing URLs, emails, and documents through three intelligent layers of defense.
                </p>
                <p>
                  Built as a Minor Project by 4 CSE students. Free. No login. Just protection.
                </p>
              </div>
            </motion.div>

            {/* Stat Cards */}
            <div className="grid grid-cols-3 gap-4 mt-8">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, delay: 0.1 }}
                className="bg-[#060D1A] border-t-3 border-t-[#00C2FF] rounded-xl p-5"
              >
                <div className="text-3xl font-semibold text-[#00C2FF] mb-1 flex items-baseline">
                  <CountUpAnimation end={12} />
                  <span>Lac+</span>
                </div>
                <p className="text-[#8BA3BC] text-xs">URLs Trained On</p>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, delay: 0.2 }}
                className="bg-[#060D1A] border-t-3 border-t-[#00C2FF] rounded-xl p-5"
              >
                <div className="text-3xl font-semibold text-[#00C2FF] mb-1 flex items-baseline">
                  <CountUpAnimation end={90} />
                  <span>%+</span>
                </div>
                <p className="text-[#8BA3BC] text-xs">Detection Accuracy</p>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, delay: 0.3 }}
                className="bg-[#060D1A] border-t-3 border-t-[#00C2FF] rounded-xl p-5"
              >
                <div className="text-3xl font-semibold text-[#00C2FF] mb-1">&lt; 3s</div>
                <p className="text-[#8BA3BC] text-xs">Average Scan Speed</p>
              </motion.div>
            </div>
          </div>

          {/* Right Column - Mockup */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="relative"
          >
            <div className="bg-[#060D1A] rounded-2xl border border-[#1E3A5F] p-6 shadow-[0_0_60px_rgba(0,194,255,0.15)]">
              {/* Mock Browser Header */}
              <div className="flex items-center gap-2 mb-4 pb-3 border-b border-[#1E3A5F]">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-[#FF3B3B]" />
                  <div className="w-3 h-3 rounded-full bg-[#FFAA00]" />
                  <div className="w-3 h-3 rounded-full bg-[#00D68F]" />
                </div>
                <div className="flex-1 bg-[#0D1F38] rounded-md px-3 py-1 text-[#8BA3BC] text-sm">
                  darkhookdefense.app/scan
                </div>
              </div>

              {/* Mock Result */}
              <div className="space-y-4">
                <div className="flex items-center justify-between bg-[#0D1F38] rounded-lg p-4 border border-[#FF3B3B]/30">
                  <div className="flex items-center gap-3">
                    <XCircle className="w-6 h-6 text-[#FF3B3B]" />
                    <div>
                      <p className="text-white font-semibold">Phishing Detected</p>
                      <p className="text-[#ffffff99] text-sm">Risk Score: 87/100</p>
                    </div>
                  </div>
                  <div className="px-4 py-2 bg-[#FF3B3B] text-white rounded-lg text-sm font-semibold">
                    DANGER
                  </div>
                </div>

                <div className="flex items-center justify-between bg-[#0D1F38] rounded-lg p-4 border border-[#00D68F]/30">
                  <div className="flex items-center gap-3">
                    <CheckCircle2 className="w-6 h-6 text-[#00D68F]" />
                    <div>
                      <p className="text-white font-semibold">Safe</p>
                      <p className="text-[#ffffff99] text-sm">Risk Score: 12/100</p>
                    </div>
                  </div>
                  <div className="px-4 py-2 bg-[#00D68F] text-white rounded-lg text-sm font-semibold">
                    SAFE
                  </div>
                </div>
              </div>

              {/* Floating Badge */}
              <motion.div
                animate={{
                  y: [-4, 4, -4]
                }}
                transition={{
                  duration: 3,
                  repeat: Infinity,
                  ease: "easeInOut"
                }}
                className="absolute -top-4 -right-4 bg-[#060D1A] border-2 border-[#00C2FF] rounded-full px-4 py-2 shadow-lg"
              >
                <p className="text-[#00C2FF] font-semibold text-sm">AI Powered</p>
              </motion.div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}