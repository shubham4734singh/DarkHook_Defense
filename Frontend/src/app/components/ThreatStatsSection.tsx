import { motion } from 'motion/react';
import { Link as LinkIcon, Mail, FileText } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

function CountUpAnimation({ end, duration = 2, suffix = '' }: { end: number; duration?: number; suffix?: string }) {
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

  return <div ref={ref}>{count.toLocaleString()}{suffix}</div>;
}

export function ThreatStatsSection() {
  return (
    <section className="bg-[#0D1F38] py-12 md:py-16">
      <div className="max-w-[1200px] mx-auto px-4">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <p className="text-[#00C2FF] font-medium text-sm tracking-[3px] mb-4 uppercase">
            // Threats Caught
          </p>
          <h2 className="text-2xl sm:text-4xl md:text-5xl font-bold text-white mb-6">
            Darkhook Is Always Watching.
          </h2>
        </motion.div>

        {/* Stats */}
        <div className="grid md:grid-cols-3 gap-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="text-center"
          >
            <div className="mb-4">
              <LinkIcon className="w-12 h-12 text-[#00C2FF] mx-auto" />
            </div>
            <div className="text-3xl sm:text-4xl md:text-5xl font-semibold text-white mb-2">
              <CountUpAnimation end={12847} />
              <span>+</span>
            </div>
            <p className="text-[#00C2FF] font-medium mb-1">Phishing URLs Detected</p>
            <p className="text-[#8BA3BC] text-sm">Since project launch</p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="text-center"
          >
            <div className="mb-4">
              <Mail className="w-12 h-12 text-[#00C2FF] mx-auto" />
            </div>
            <div className="text-3xl sm:text-4xl md:text-5xl font-semibold text-white mb-2">
              <CountUpAnimation end={8203} />
              <span>+</span>
            </div>
            <p className="text-[#00C2FF] font-medium mb-1">Malicious Emails Flagged</p>
            <p className="text-[#8BA3BC] text-sm">Since project launch</p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="text-center"
          >
            <div className="mb-4">
              <FileText className="w-12 h-12 text-[#00C2FF] mx-auto" />
            </div>
            <div className="text-3xl sm:text-4xl md:text-5xl font-semibold text-white mb-2">
              <CountUpAnimation end={3991} />
              <span>+</span>
            </div>
            <p className="text-[#00C2FF] font-medium mb-1">Infected Documents Found</p>
            <p className="text-[#8BA3BC] text-sm">Since project launch</p>
          </motion.div>
        </div>
      </div>
    </section>
  );
}