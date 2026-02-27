import { motion } from 'motion/react';
import { Check, X } from 'lucide-react';

const features = [
  { name: 'URL Scan', darkhook: true, virustotal: true, manual: false },
  { name: 'Email Header Analysis', darkhook: true, virustotal: false, manual: false },
  { name: 'Document OCR Scan', darkhook: true, virustotal: false, manual: false },
  { name: 'QR Code Detection', darkhook: true, virustotal: false, manual: false },
  { name: 'Module Chaining', darkhook: true, virustotal: false, manual: false },
  { name: 'Macro Detection', darkhook: true, virustotal: false, manual: false },
  { name: 'Free & No Login', darkhook: true, virustotal: true, manual: true },
  { name: 'Results in < 3 Seconds', darkhook: true, virustotal: false, manual: false },
];

export function ComparisonSection() {
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
            // Why Darkhook
          </p>
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
            We See What Others Miss.
          </h2>
        </motion.div>

        {/* Table */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="max-w-[860px] mx-auto bg-[#060D1A] border border-[#1E3A5F] rounded-2xl overflow-hidden"
        >
          {/* Header Row */}
          <div className="grid grid-cols-4 bg-[#060D1A] border-b border-[#1E3A5F]">
            <div className="p-4 font-semibold text-white">Feature</div>
            <div className="p-4 font-semibold text-[#00C2FF] border-l-4 border-[#00C2FF] bg-[#00C2FF]/5">
              Darkhook Defense
            </div>
            <div className="p-4 font-semibold text-white">VirusTotal</div>
            <div className="p-4 font-semibold text-white">Manual Check</div>
          </div>

          {/* Data Rows */}
          {features.map((feature, index) => (
            <div
              key={feature.name}
              className={`grid grid-cols-4 border-b border-[#1E3A5F] last:border-b-0 ${
                index % 2 === 0 ? 'bg-[#0D1F38]' : 'bg-[#0a1829]'
              }`}
            >
              <div className="p-4 text-[#8BA3BC]">{feature.name}</div>
              <div className="p-4 border-l-4 border-[#00C2FF] bg-[#00C2FF]/5">
                {feature.darkhook ? (
                  <Check className="w-5 h-5 text-[#00D68F]" />
                ) : (
                  <X className="w-5 h-5 text-[#FF3B3B]" />
                )}
              </div>
              <div className="p-4">
                {feature.virustotal ? (
                  <Check className="w-5 h-5 text-[#00D68F]" />
                ) : (
                  <X className="w-5 h-5 text-[#FF3B3B]" />
                )}
              </div>
              <div className="p-4">
                {feature.manual ? (
                  <Check className="w-5 h-5 text-[#00D68F]" />
                ) : (
                  <X className="w-5 h-5 text-[#FF3B3B]" />
                )}
              </div>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}