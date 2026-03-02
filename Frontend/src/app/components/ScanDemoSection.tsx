import { motion } from 'motion/react';
import { Link as LinkIcon, Mail, FileText } from 'lucide-react';
import { Link } from 'react-router';

export function ScanDemoSection() {
  const scanTypes = [
    {
      icon: LinkIcon,
      title: 'URL Scanner',
      description: 'Scan suspicious links and websites for phishing threats',
      path: '/scan/url'
    },
    {
      icon: Mail,
      title: 'Email Scanner',
      description: 'Analyze emails for phishing attempts and malicious content',
      path: '/scan/email'
    },
    {
      icon: FileText,
      title: 'Document Scanner',
      description: 'Check documents and attachments for hidden threats',
      path: '/scan/document'
    }
  ];

  return (
    <section id="demo" className="py-16 bg-[#060D1A]">
      <div className="container mx-auto px-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-10"
        >
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-3">
            Try Our <span className="text-[#00C2FF]">Live Scan Demo</span>
          </h2>
          <p className="text-[#8BA3BC] text-base max-w-2xl mx-auto">
            Experience our AI-powered threat detection in action
          </p>
        </motion.div>

        <div className="grid md:grid-cols-3 gap-6 max-w-5xl mx-auto">
          {scanTypes.map((scan, index) => (
            <motion.div
              key={scan.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.1 }}
              className="bg-[#0D1F38] rounded-lg p-6 border border-[#1E3A5F] hover:border-[#00C2FF]/50 transition-all duration-300"
            >
              <div className="flex flex-col items-center text-center">
                <div className="w-16 h-16 bg-[#00C2FF]/10 rounded-full flex items-center justify-center mb-4">
                  <scan.icon className="w-8 h-8 text-[#00C2FF]" />
                </div>
                <h3 className="text-xl font-semibold text-white mb-2">
                  {scan.title}
                </h3>
                <p className="text-[#8BA3BC] text-sm mb-6">
                  {scan.description}
                </p>
                <Link
                  to={scan.path}
                  className="w-full px-6 py-3 bg-[#00C2FF] hover:bg-[#00A8E0] text-[#060D1A] font-semibold rounded-lg transition-all duration-300 hover:scale-105"
                >
                  Scan Now
                </Link>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}