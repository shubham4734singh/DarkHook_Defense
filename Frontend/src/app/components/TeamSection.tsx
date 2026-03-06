import { motion } from 'motion/react';
import { Github, Linkedin, Code, AtSign, FileText, Sparkles, Globe } from 'lucide-react';

const team = [
  {
    name: 'Shubham',
    role: 'Backend Lead',
    module: 'URL Shield',
    moduleColor: 'bg-blue-500',
    bio: 'Built the brain behind URL AI',
    image: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=400&h=400&fit=crop',
    github: 'https://github.com/shubham4734singh',
    linkedin: 'https://www.linkedin.com/in/shubham4734singh',
    portfolio: 'https://shubhamcybersky.in',
    initial: 'S',
    gradient: 'linear-gradient(135deg, #092C56 0%, #0D3B6E 100%)',
    roleIcon: Code,
    accentColor: '#A9CBE0'
  },
  {
    name: 'Naman',
    role: 'Email Module',
    module: 'Mail Trap',
    moduleColor: 'bg-green-500',
    bio: 'Trained the model that reads every inbox',
    image: 'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=400&h=400&fit=crop',
    github: '#',
    linkedin: 'https://www.linkedin.com/in/naman-singh-sikarwar-872a92237',
    initial: 'N',
    gradient: 'linear-gradient(135deg, #092C56 0%, #0D3B2A 100%)',
    roleIcon: AtSign,
    accentColor: '#10B981'
  },
  {
    name: 'Poonam',
    role: 'Document Module',
    module: 'Doc Scanner',
    moduleColor: 'bg-orange-500',
    bio: 'Made documents confess their secrets',
    image: 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=400&h=400&fit=crop',
    github: 'https://github.com/Poonam0709',
    linkedin: 'https://www.linkedin.com/in/poonam-soni-89aa02282/',
    initial: 'P',
    gradient: 'linear-gradient(135deg, #092C56 0%, #3B2A0D 100%)',
    roleIcon: FileText,
    accentColor: '#F59E0B'
  },
  {
    name: 'Disha',
    role: 'Frontend Lead',
    module: 'UI / UX',
    moduleColor: 'bg-red-500',
    bio: 'Designed every pixel you see on this page',
    image: 'https://images.unsplash.com/photo-1438761681033-6461ffad8d80?w=400&h=400&fit=crop',
    github: 'https://github.com/mysterious-glitch',
    linkedin: 'https://www.linkedin.com/in/disha-agarwal-a4717b290/',
    initial: 'D',
    gradient: 'linear-gradient(135deg, #092C56 0%, #2A0D3B 100%)',
    roleIcon: Sparkles,
    accentColor: '#668CA9'
  }
];

export function TeamSection() {
  return (
    <section id="team" className="bg-[#060D1A] py-12 md:py-16">
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
            // The Team
          </p>
          <h2 className="text-2xl sm:text-4xl md:text-5xl font-bold text-white mb-6">
            Four Minds. One Mission. Zero Phishing.
          </h2>
          <p className="text-[#8BA3BC] text-lg">
            Each member owns a full detection module end-to-end.
          </p>
        </motion.div>

        {/* Team Cards */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
          {team.map((member, index) => (
            <motion.div
              key={member.name}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6, delay: index * 0.1 }}
              whileHover={{
                y: -4,
                borderColor: '#00C2FF',
                boxShadow: '0 0 28px rgba(0,194,255,0.2)'
              }}
              className="bg-[#0D1F38] border border-[#1E3A5F] rounded-2xl p-6 text-center transition-all duration-300 relative overflow-hidden"
              style={{
                borderTop: `3px solid ${member.accentColor}`
              }}
            >
              {/* Avatar Circle */}
              <div className="mb-4 relative inline-block">
                {/* Avatar with Gradient Background */}
                <div 
                  className="w-20 h-20 sm:w-24 sm:h-24 rounded-full mx-auto flex items-center justify-center relative"
                  style={{
                    background: member.gradient,
                    border: '3px solid #A9CBE0',
                    boxShadow: '0 0 20px rgba(169,203,224,0.3)'
                  }}
                >
                  {/* Initial */}
                  <span 
                    style={{
                      fontFamily: 'Raleway, sans-serif',
                      fontSize: '32px',
                      fontWeight: 700,
                      color: '#A9CBE0'
                    }}
                  >
                    {member.initial}
                  </span>
                </div>

                {/* Role Icon - Bottom Right Overlay */}
                <div 
                  className="absolute bottom-0 right-0 w-6 h-6 rounded-full flex items-center justify-center"
                  style={{
                    background: '#092C56',
                    border: '2px solid #225688'
                  }}
                >
                  <member.roleIcon className="w-3.5 h-3.5" style={{ color: '#A9CBE0' }} />
                </div>
              </div>

              {/* Name */}
              <h3 className="text-xl font-semibold text-white mb-1">
                {member.name}
              </h3>

              {/* Role */}
              <p className="text-[#00C2FF] text-xs font-medium tracking-[2px] uppercase mb-3">
                {member.role}
              </p>

              {/* Module Badge */}
              <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-[#060D1A] border border-[#1E3A5F] rounded-full mb-4">
                <div className={`w-2 h-2 rounded-full ${member.moduleColor}`} />
                <span className="text-[#00C2FF] text-xs font-medium">{member.module}</span>
              </div>

              {/* Divider */}
              <div className="h-px bg-[#1E3A5F] my-4 opacity-30" />

              {/* Bio */}
              <p className="text-[#8BA3BC] text-sm italic leading-relaxed mb-4">
                {member.bio}
              </p>

              {/* Social Icons */}
              <div className="flex items-center justify-center gap-3">
                <a
                  href={member.github}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
                >
                  <Github className="w-5 h-5" />
                </a>
                <a
                  href={member.linkedin}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
                >
                  <Linkedin className="w-5 h-5" />
                </a>
                {member.portfolio && (
                  <a
                    href={member.portfolio}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[#8BA3BC] hover:text-[#00C2FF] transition-colors"
                  >
                    <Globe className="w-5 h-5" />
                  </a>
                )}
              </div>
            </motion.div>
          ))}
        </div>

        {/* College Info */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center"
        >
          <div className="inline-flex items-center gap-2 px-6 py-3 bg-[#0D1F38] border border-[#1E3A5F] rounded-xl">
            <span className="text-[#8BA3BC]">
              🎓 Minor Project — Computer Science Engineering • Academic Year 2025–26
            </span>
          </div>
        </motion.div>
      </div>
    </section>
  );
}