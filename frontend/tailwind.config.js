/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Official Hackathon Enterprise Security Palette
        navy: {
          950: '#071426', // Main Background
          900: '#0B1729', // Sidebar & Deep Headers
          850: '#0E1C33', // Intermediate Containers
          800: '#11213A', // Primary Cards
          750: '#132641', // Card Hover State
          700: '#162B46', // Secondary Panels
          600: '#1E3A5F', // Active Interactive Elements
        },
        // Cybersecurity Brand Accents
        cyan: {
          400: '#22D3EE', // Primary Cyber Accent
          500: '#06B6D4',
          600: '#0891B2',
        },
        blue: {
          500: '#3B82F6', // Secondary Brand Blue
          600: '#2563EB',
        },
        slate: {
          100: '#F8FAFC', // Main High-Contrast Text
          300: '#CBD5E1',
          400: '#B8C6D9', // Secondary Muted Text
          500: '#64748B',
        },
        // Semantic Indicators
        status: {
          success: '#22C55E', // Green Success
          warning: '#F59E0B', // Amber Warning
          critical: '#F43F5E', // Rose Critical
        },
        // Severity colors
        severity: {
          critical: '#F43F5E',
          high: '#F97316',
          medium: '#F59E0B',
          low: '#3B82F6',
          info: '#64748B',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
      },
      boxShadow: {
        'glow-blue': '0 0 20px rgba(37, 99, 235, 0.25)',
        'glow-cyan': '0 0 25px rgba(6, 182, 212, 0.3)',
        'glow-matrix': '0 0 25px rgba(16, 185, 129, 0.3)',
        'glow-red': '0 0 20px rgba(239, 68, 68, 0.25)',
        'card': '0 4px 20px -2px rgba(0, 0, 0, 0.7), 0 2px 6px -1px rgba(0, 0, 0, 0.5)',
        'hacker': '0 0 1px 1px rgba(6, 182, 212, 0.2), 0 10px 30px -5px rgba(0, 0, 0, 0.8)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.3s ease-in-out',
        'slide-in': 'slideIn 0.3s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideIn: {
          '0%': { transform: 'translateX(-10px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
