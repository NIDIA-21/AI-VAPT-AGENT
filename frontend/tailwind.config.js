/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Ultra-dark stealth navy / hacker black backgrounds
        navy: {
          950: '#020611', // Deepest pitch void
          900: '#040916', // Command shell background
          850: '#070e1f', // Sub-panels
          800: '#091226', // Tactical cards & modules
          750: '#0c1730', // Card hover state
          700: '#0f1d3d', // Elevated borders & dialogs
          600: '#15274f', // Active interactive states
        },
        // Charcoal surfaces
        charcoal: {
          950: '#020408',
          900: '#090d16',
          800: '#121826',
          700: '#1e2638',
          600: '#2d374d',
        },
        // Cyber & Hacker terminal accents
        cyber: {
          black: '#01040a',
          dark: '#030712',
          panel: '#060b18',
          border: '#111d36',
          cyan: '#00f0ff',
          neon: '#06b6d4',
          matrix: '#10b981',
          lime: '#22c55e',
          amber: '#f59e0b',
          crimson: '#f43f5e',
        },
        // Electric blue/cyan accents
        electric: {
          blue: '#2563eb',
          cyan: '#06b6d4',
          indigo: '#4f46e5',
        },
        // Severity colors
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#f59e0b',
          low: '#3b82f6',
          info: '#6b7280',
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
