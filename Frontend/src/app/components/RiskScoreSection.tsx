import { motion } from 'motion/react';
import { CheckCircle, AlertTriangle, XCircle } from 'lucide-react';

const zones = [
  {
    icon: CheckCircle,
    color: '#00D68F',
    title: 'Safe',
    range: '0–39',
    description: 'No known threat signals detected. Safe to open.'
  },
  {
    icon: AlertTriangle,
    color: '#FFAA00',
    title: 'Suspicious',
    range: '40–69',
    description: 'Some red flags found. Proceed with caution.'
  },
  {
    icon: XCircle,
    color: '#FF3B3B',
    title: 'Phishing',
    range: '70–100',
    description: 'High-confidence threat. Do not click or open.'
  }
];

export function RiskScoreSection() {
  return (
    <section className="bg-[#060D1A] py-12 md:py-16">
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
            // Risk Score
          </p>
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
            What Does Your Score Mean?
          </h2>
        </motion.div>

        {/* Score Bar */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="max-w-[700px] mx-auto mb-16"
        >
          {/* Gradient Bar */}
          <div className="relative h-3 rounded-full mb-8 overflow-hidden" style={{
            background: 'linear-gradient(90deg, #00D68F 0%, #FFAA00 50%, #FF3B3B 100%)'
          }}>
          </div>

          {/* Markers */}
          <div className="flex justify-between text-center mb-8">
            <div className="flex-1">
              <p className="text-[#00C2FF] font-semibold text-lg mb-1">0</p>
              <p className="text-[#8BA3BC] text-sm">0–39</p>
              <p className="text-[#00D68F] font-semibold text-lg mt-3">🟢 SAFE</p>
              <p className="text-[#8BA3BC] text-sm mt-1">No threat found</p>
            </div>
            <div className="flex-1">
              <p className="text-[#00C2FF] font-semibold text-lg mb-1">40–69</p>
              <p className="text-[#8BA3BC] text-sm">Medium Risk</p>
              <p className="text-[#FFAA00] font-semibold text-lg mt-3">🟡 SUSPICIOUS</p>
              <p className="text-[#8BA3BC] text-sm mt-1">Proceed carefully</p>
            </div>
            <div className="flex-1">
              <p className="text-[#00C2FF] font-semibold text-lg mb-1">100</p>
              <p className="text-[#8BA3BC] text-sm">70–100</p>
              <p className="text-[#FF3B3B] font-semibold text-lg mt-3">🔴 PHISHING</p>
              <p className="text-[#8BA3BC] text-sm mt-1">Do not open</p>
            </div>
          </div>
        </motion.div>

        {/* Zone Cards */}
        <div className="grid md:grid-cols-3 gap-6">
          {zones.map((zone, index) => (
            <motion.div
              key={zone.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6, delay: 0.1 * index }}
              className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-6"
              style={{ borderTopColor: zone.color, borderTopWidth: '3px' }}
            >
              <div className="flex items-center gap-3 mb-4">
                <zone.icon className="w-8 h-8" style={{ color: zone.color }} />
                <h3 className="text-xl font-semibold" style={{ color: zone.color }}>
                  {zone.title} ({zone.range})
                </h3>
              </div>
              <p className="text-[#8BA3BC] leading-relaxed">
                {zone.description}
              </p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}