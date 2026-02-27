import { motion, AnimatePresence } from 'motion/react';
import { Plus, Minus } from 'lucide-react';
import { useState } from 'react';

const faqs = [
  {
    question: 'Is my data stored after scanning?',
    answer: 'No. Darkhook processes your input in real-time and does not store URLs, email content, or uploaded files.'
  },
  {
    question: 'What file types can I scan?',
    answer: 'PDF, DOCX, XLSX, PPTX for documents, and .eml or raw paste for emails.'
  },
  {
    question: 'How accurate is the detection?',
    answer: 'Our URL model achieves 92%+ accuracy, email model 95%+. All trained on real-world phishing datasets.'
  },
  {
    question: 'Can it detect zero-day phishing attacks?',
    answer: 'Our rule-based engine catches structural patterns regardless of known threat databases, giving partial protection even against new threats.'
  },
  {
    question: 'Is this open source?',
    answer: 'Yes. The full source code is available on GitHub.'
  }
];

export function FAQSection() {
  const [openIndex, setOpenIndex] = useState<number | null>(null);

  return (
    <section className="bg-[#0D1F38] py-12 md:py-16">
      <div className="max-w-[720px] mx-auto px-4">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-12"
        >
          <p className="text-[#00C2FF] font-medium text-sm tracking-[3px] mb-4 uppercase">
            // FAQ
          </p>
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
            Got Questions? We've Got Answers.
          </h2>
        </motion.div>

        {/* FAQ Items */}
        <div className="space-y-3">
          {faqs.map((faq, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: index * 0.05 }}
              className={`bg-[#060D1A] border rounded-xl overflow-hidden transition-all ${
                openIndex === index ? 'border-[#00C2FF] border-l-4' : 'border-[#1E3A5F]'
              }`}
            >
              <button
                onClick={() => setOpenIndex(openIndex === index ? null : index)}
                className="w-full flex items-center justify-between p-5 text-left hover:bg-[#0D1F38]/30 transition-colors"
              >
                <span className="text-white font-semibold text-lg pr-4">
                  {faq.question}
                </span>
                {openIndex === index ? (
                  <Minus className="w-5 h-5 text-[#00C2FF] flex-shrink-0" />
                ) : (
                  <Plus className="w-5 h-5 text-[#00C2FF] flex-shrink-0" />
                )}
              </button>
              
              <AnimatePresence>
                {openIndex === index && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.3 }}
                    className="overflow-hidden"
                  >
                    <div className="px-5 pb-5 pt-0">
                      <p className="text-[#8BA3BC] leading-relaxed">
                        {faq.answer}
                      </p>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}