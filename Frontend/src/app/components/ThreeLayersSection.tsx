import { motion } from 'motion/react';
import { Link as LinkIcon, Mail, FileText, ArrowRight, ArrowDown, Info } from 'lucide-react';

const layers = [
  {
    icon: LinkIcon,
    badge: 'ML-Powered',
    badgeColor: 'bg-blue-500',
    title: 'URL Shield',
    subtitle: 'Catch the hook in the link',
    features: [
      '20+ feature extraction',
      'Typosquatting detection',
      'IP address pattern check',
      'Random Forest + XGBoost',
      '92%+ accuracy'
    ],
    iconBg: '#0D2137',
    topGlow: 'inset 0 1px 0 rgba(169,203,224,0.3)',
    dotColor: '#A9CBE0'
  },
  {
    icon: Mail,
    badge: 'Header + ML Analysis',
    badgeColor: 'bg-green-500',
    title: 'Mail Trap',
    subtitle: 'Expose the lure in the inbox',
    features: [
      'SPF/DKIM/DMARC analysis',
      'Sender spoofing detect',
      '50+ urgency keywords',
      'Lookalike domain detect',
      '95%+ accuracy'
    ],
    iconBg: '#0D2318',
    topGlow: 'inset 0 1px 0 rgba(16,185,129,0.2)',
    dotColor: '#10B981'
  },
  {
    icon: FileText,
    badge: 'Multi-Format + OCR',
    badgeColor: 'bg-orange-500',
    title: 'Doc Scanner',
    subtitle: 'See what hides in the pages',
    features: [
      'PDF DOCX XLSX PPTX',
      'Macro detection (olevba)',
      'OCR image text extract',
      'QR code URL scanning',
      'JS-in-PDF risk scoring'
    ],
    iconBg: '#1F1509',
    topGlow: 'inset 0 1px 0 rgba(245,158,11,0.2)',
    dotColor: '#F59E0B'
  }
];

export function ThreeLayersSection() {
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
            ⚡ Three Layers of Defense
          </p>
          <h2 className="text-2xl sm:text-4xl md:text-5xl font-bold text-white mb-6">
            One Threat Missed Is One Too Many.
          </h2>
          <p className="text-[#ffffff99] text-lg max-w-[600px] mx-auto">
            Every scan passes through three independent AI engines. All three must clear before we call it safe.
          </p>
        </motion.div>

        {/* Cards */}
        <div className="grid md:grid-cols-3 gap-6 mb-12">
          {layers.map((layer, index) => (
            <motion.div
              key={layer.title}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6, delay: index * 0.1 }}
              whileHover={{ 
                y: -4, 
                borderColor: '#00C2FF',
                boxShadow: '0 0 28px rgba(0,194,255,0.3)'
              }}
              className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-8 transition-all duration-300 relative"
              style={{ boxShadow: layer.topGlow }}
            >
              {/* Corner Dot */}
              <div 
                className="absolute top-4 right-4 w-[6px] h-[6px] rounded-full"
                style={{ backgroundColor: layer.dotColor }}
              />

              {/* Icon Circle */}
              <div className="mb-6">
                <div 
                  className="w-14 h-14 rounded-full flex items-center justify-center"
                  style={{ backgroundColor: layer.iconBg }}
                >
                  <layer.icon className="w-7 h-7 text-[#A9CBE0]" strokeWidth={1.5} />
                </div>
              </div>

              {/* Title */}
              <h3 className="text-2xl font-semibold text-white mb-2">
                {layer.title}
              </h3>

              {/* Subtitle */}
              <p className="text-[#00C2FF] font-semibold mb-6 text-sm">
                {layer.subtitle}
              </p>

              {/* Features */}
              <ul className="space-y-3 mb-6">
                {layer.features.map((feature) => (
                  <li key={feature} className="flex items-start gap-2 text-[#8BA3BC] text-sm">
                    <span className="text-[#00C2FF] mt-0.5">✦</span>
                    {feature}
                  </li>
                ))}
              </ul>

              {/* Badge */}
              <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-[#060D1A] border border-[#1E3A5F] rounded-full">
                <div className={`w-2 h-2 rounded-full ${layer.badgeColor}`} />
                <span className="text-[#00C2FF] text-xs font-medium">{layer.badge}</span>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Module Chain - Desktop Version (hidden on mobile) */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="hidden md:block bg-[#0D1F38] border border-[#1E3A5F] rounded-xl p-8"
        >
          <h3 className="text-white font-semibold text-xl mb-6 text-center">
            Module Chaining: How They Work Together
          </h3>
          
          <div className="flex flex-col md:flex-row items-center justify-center gap-4 flex-wrap">
            {/* Document Flow */}
            <div className="flex items-center gap-3">
              <div className="px-4 py-2 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-white text-sm">
                📄 Document
              </div>
              <motion.div
                animate={{ x: [0, 5, 0] }}
                transition={{ duration: 1.5, repeat: Infinity }}
              >
                <ArrowRight className="w-5 h-5 text-[#00C2FF]" />
              </motion.div>
              <div className="px-4 py-2 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-white text-sm">
                🔗 URLs Found
              </div>
              <motion.div
                animate={{ x: [0, 5, 0] }}
                transition={{ duration: 1.5, repeat: Infinity, delay: 0.3 }}
              >
                <ArrowRight className="w-5 h-5 text-[#00C2FF]" />
              </motion.div>
              <div className="px-4 py-2 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-white text-sm">
                🔗 URL Shield
              </div>
            </div>

            <div className="hidden md:block w-px h-12 bg-[#1E3A5F]" />

            {/* Email Flow */}
            <div className="flex items-center gap-3">
              <div className="px-4 py-2 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-white text-sm">
                📧 Email
              </div>
              <motion.div
                animate={{ x: [0, 5, 0] }}
                transition={{ duration: 1.5, repeat: Infinity }}
              >
                <ArrowRight className="w-5 h-5 text-[#00C2FF]" />
              </motion.div>
              <div className="px-4 py-2 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-white text-sm">
                📎 Attachment
              </div>
              <motion.div
                animate={{ x: [0, 5, 0] }}
                transition={{ duration: 1.5, repeat: Infinity, delay: 0.3 }}
              >
                <ArrowRight className="w-5 h-5 text-[#00C2FF]" />
              </motion.div>
              <div className="px-4 py-2 bg-[#060D1A] border border-[#1E3A5F] rounded-lg text-white text-sm">
                📄 Doc Scanner
              </div>
            </div>
          </div>
        </motion.div>

        {/* Module Chain - Mobile Version (shown only on mobile) */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="md:hidden"
          style={{
            background: '#225688',
            border: '1px solid #668CA9',
            borderRadius: '12px',
            padding: '20px'
          }}
        >
          {/* Title Row */}
          <div className="flex items-center justify-between mb-6">
            <h3 
              style={{
                fontFamily: 'Raleway, sans-serif',
                fontSize: '15px',
                fontWeight: 600,
                color: '#F0F5F4'
              }}
            >
              Module Chaining
            </h3>
            <Info className="w-4 h-4" style={{ color: '#668CA9' }} />
          </div>

          {/* Chain 1 - Document Chain */}
          <div className="mb-6">
            <div 
              className="mb-3"
              style={{
                fontFamily: 'Raleway, sans-serif',
                fontSize: '12px',
                fontWeight: 500,
                color: '#A9CBE0',
                letterSpacing: '2px'
              }}
            >
              📄 DOCUMENT SCAN CHAIN
            </div>

            {/* Node 1 */}
            <div 
              className="w-full flex items-center gap-3"
              style={{
                background: '#092C56',
                border: '1px solid #668CA9',
                borderRadius: '8px',
                padding: '10px 16px'
              }}
            >
              <span style={{ fontSize: '16px', color: '#A9CBE0' }}>📄</span>
              <span 
                style={{
                  fontFamily: 'Raleway, sans-serif',
                  fontSize: '14px',
                  fontWeight: 500,
                  color: '#F0F5F4'
                }}
              >
                Document Upload
              </span>
            </div>

            {/* Arrow Down */}
            <div className="flex flex-col items-center py-2">
              <div 
                style={{
                  width: '2px',
                  height: '16px',
                  background: '#A9CBE0',
                  opacity: 0.5
                }}
              />
              <motion.div
                animate={{ y: [0, 3, 0] }}
                transition={{ duration: 1.5, repeat: Infinity }}
              >
                <ArrowDown className="w-4 h-4" style={{ color: '#A9CBE0' }} />
              </motion.div>
            </div>

            {/* Node 2 */}
            <div 
              className="w-full flex items-center gap-3"
              style={{
                background: '#092C56',
                border: '1px solid #668CA9',
                borderRadius: '8px',
                padding: '10px 16px'
              }}
            >
              <span style={{ fontSize: '16px', color: '#A9CBE0' }}>🔍</span>
              <span 
                style={{
                  fontFamily: 'Raleway, sans-serif',
                  fontSize: '14px',
                  fontWeight: 500,
                  color: '#F0F5F4'
                }}
              >
                URLs Extracted
              </span>
            </div>

            {/* Arrow Down */}
            <div className="flex flex-col items-center py-2">
              <div 
                style={{
                  width: '2px',
                  height: '16px',
                  background: '#A9CBE0',
                  opacity: 0.5
                }}
              />
              <motion.div
                animate={{ y: [0, 3, 0] }}
                transition={{ duration: 1.5, repeat: Infinity, delay: 0.3 }}
              >
                <ArrowDown className="w-4 h-4" style={{ color: '#A9CBE0' }} />
              </motion.div>
            </div>

            {/* Node 3 */}
            <div 
              className="w-full flex items-center gap-3"
              style={{
                background: '#092C56',
                border: '1px solid #668CA9',
                borderRadius: '8px',
                padding: '10px 16px'
              }}
            >
              <span style={{ fontSize: '16px', color: '#A9CBE0' }}>🔗</span>
              <span 
                style={{
                  fontFamily: 'Raleway, sans-serif',
                  fontSize: '14px',
                  fontWeight: 500,
                  color: '#F0F5F4'
                }}
              >
                URL Shield Scans
              </span>
            </div>
          </div>

          {/* Divider */}
          <div 
            style={{
              height: '1px',
              background: '#668CA9',
              opacity: 0.3,
              margin: '24px 0'
            }}
          />

          {/* Chain 2 - Email Chain */}
          <div>
            <div 
              className="mb-3"
              style={{
                fontFamily: 'Raleway, sans-serif',
                fontSize: '12px',
                fontWeight: 500,
                color: '#A9CBE0',
                letterSpacing: '2px'
              }}
            >
              📧 EMAIL SCAN CHAIN
            </div>

            {/* Node 1 */}
            <div 
              className="w-full flex items-center gap-3"
              style={{
                background: '#092C56',
                border: '1px solid #668CA9',
                borderRadius: '8px',
                padding: '10px 16px'
              }}
            >
              <span style={{ fontSize: '16px', color: '#A9CBE0' }}>📧</span>
              <span 
                style={{
                  fontFamily: 'Raleway, sans-serif',
                  fontSize: '14px',
                  fontWeight: 500,
                  color: '#F0F5F4'
                }}
              >
                Email Upload
              </span>
            </div>

            {/* Arrow Down */}
            <div className="flex flex-col items-center py-2">
              <div 
                style={{
                  width: '2px',
                  height: '16px',
                  background: '#A9CBE0',
                  opacity: 0.5
                }}
              />
              <motion.div
                animate={{ y: [0, 3, 0] }}
                transition={{ duration: 1.5, repeat: Infinity }}
              >
                <ArrowDown className="w-4 h-4" style={{ color: '#A9CBE0' }} />
              </motion.div>
            </div>

            {/* Node 2 */}
            <div 
              className="w-full flex items-center gap-3"
              style={{
                background: '#092C56',
                border: '1px solid #668CA9',
                borderRadius: '8px',
                padding: '10px 16px'
              }}
            >
              <span style={{ fontSize: '16px', color: '#A9CBE0' }}>📎</span>
              <span 
                style={{
                  fontFamily: 'Raleway, sans-serif',
                  fontSize: '14px',
                  fontWeight: 500,
                  color: '#F0F5F4'
                }}
              >
                Attachment Found
              </span>
            </div>

            {/* Arrow Down */}
            <div className="flex flex-col items-center py-2">
              <div 
                style={{
                  width: '2px',
                  height: '16px',
                  background: '#A9CBE0',
                  opacity: 0.5
                }}
              />
              <motion.div
                animate={{ y: [0, 3, 0] }}
                transition={{ duration: 1.5, repeat: Infinity, delay: 0.3 }}
              >
                <ArrowDown className="w-4 h-4" style={{ color: '#A9CBE0' }} />
              </motion.div>
            </div>

            {/* Node 3 */}
            <div 
              className="w-full flex items-center gap-3"
              style={{
                background: '#092C56',
                border: '1px solid #668CA9',
                borderRadius: '8px',
                padding: '10px 16px'
              }}
            >
              <span style={{ fontSize: '16px', color: '#A9CBE0' }}>📄</span>
              <span 
                style={{
                  fontFamily: 'Raleway, sans-serif',
                  fontSize: '14px',
                  fontWeight: 500,
                  color: '#F0F5F4'
                }}
              >
                Doc Scanner Reads
              </span>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}