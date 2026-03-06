import { motion } from 'motion/react';
import { Upload, Settings, Brain, Shield, Zap } from 'lucide-react';

const steps = [
  {
    number: '1',
    icon: Upload,
    title: 'Input',
    description: 'Paste a URL, upload a .eml email file, or drag and drop a document'
  },
  {
    number: '2',
    icon: Settings,
    title: 'Extract',
    description: '20+ features pulled automatically — headers, keywords, entropy, structure'
  },
  {
    number: '3',
    icon: Brain,
    title: 'Analyze',
    description: 'ML model + rule-based engine fires simultaneously across all extracted signals'
  },
  {
    number: '4',
    icon: Shield,
    title: 'Result',
    description: 'Risk score 0–100, clear verdict, and a full breakdown of every red flag found'
  }
];

export function HowItWorksSection() {
  return (
    <section id="how-it-works" className="bg-[#0D1F38] py-12 md:py-16">
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
            // How It Works
          </p>
          <h2 className="text-2xl sm:text-4xl md:text-5xl font-bold text-white mb-6">
            Three Steps Between You and a Threat.
          </h2>
        </motion.div>

        {/* Steps */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-8 mb-12 relative">
          {steps.map((step, index) => (
            <motion.div
              key={step.number}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6, delay: index * 0.1 }}
              className="relative bg-[#060D1A] border border-[#1E3A5F] rounded-2xl p-6"
            >
              {/* Background Number */}
              <div className="absolute top-4 right-4 text-8xl font-bold text-[#00C2FF] opacity-10">
                {step.number}
              </div>

              {/* Icon */}
              <div className="relative z-10 mb-4 w-14 h-14 bg-[#0D1F38] rounded-full flex items-center justify-center">
                <step.icon className="w-7 h-7 text-[#00C2FF]" strokeWidth={1.5} />
              </div>

              {/* Content */}
              <h3 className="relative z-10 text-xl font-semibold text-white mb-3">
                {step.title}
              </h3>
              <p className="relative z-10 text-[#ffffff99] text-sm leading-relaxed">
                {step.description}
              </p>

              {/* Arrow for desktop - positioned between cards */}
              {index < steps.length - 1 && (
                <div className="hidden lg:block absolute left-[calc(100%+0.5rem)] top-1/2 -translate-y-1/2 z-20 w-8">
                  <motion.div
                    animate={{ x: [0, 5, 0] }}
                    transition={{ duration: 1.5, repeat: Infinity, delay: index * 0.2 }}
                    className="flex items-center justify-center"
                  >
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="text-[#00C2FF]">
                      <path d="M5 12h14m-7-7l7 7-7 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                  </motion.div>
                </div>
              )}
            </motion.div>
          ))}
        </div>

        {/* Speed Highlight */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="bg-[#060D1A] border border-[#1E3A5F] rounded-xl p-6 text-center max-w-[700px] mx-auto"
        >
          <div className="flex items-center justify-center gap-2 mb-3">
            <Zap className="w-5 h-5 text-[#00C2FF]" />
            <p className="text-white font-semibold text-lg">
              Average scan time: <span className="text-[#00C2FF]">&lt; 3 seconds</span>
            </p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-6 text-sm">
            <span className="text-[#8BA3BC]">
              URL: <span className="text-[#00C2FF] font-semibold">~0.8s</span>
            </span>
            <span className="text-[#1E3A5F]">|</span>
            <span className="text-[#8BA3BC]">
              Email: <span className="text-[#00C2FF] font-semibold">~1.2s</span>
            </span>
            <span className="text-[#1E3A5F]">|</span>
            <span className="text-[#8BA3BC]">
              Document: <span className="text-[#00C2FF] font-semibold">~2.5s</span>
            </span>
          </div>
        </motion.div>
      </div>
    </section>
  );
}