/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      colors: {
        brand: {
          main: '#06080B',
          sidebar: '#0A0D12',
          panel: '#11161D',
          'panel-soft': '#171E27',
          gold: '#C9A227',
          'gold-bright': '#E2C15A',
          'gold-soft': '#A8841F',
          ivory: '#F3E8C8',
          slate: '#202936',
          steel: '#344050',
        },
        border: {
          muted: '#232B36',
          strong: '#384252',
        },
        text: {
          primary: '#F5F7FA',
          secondary: '#C8D0DA',
          muted: '#8E98A6',
        },
        success: {
          DEFAULT: '#22C55E',
          50: '#22C55E0d',
          100: '#22C55E1a',
          200: '#22C55E33',
        },
        warning: {
          DEFAULT: '#F59E0B',
          50: '#F59E0B0d',
          100: '#F59E0B1a',
          200: '#F59E0B33',
        },
        danger: {
          DEFAULT: '#EF4444',
          50: '#EF44440d',
          100: '#EF44441a',
          200: '#EF444433',
          critical: '#DC2626',
        },
        info: {
          DEFAULT: '#60A5FA',
          50: '#60A5FA0d',
          100: '#60A5FA1a',
          200: '#60A5FA33',
        },
      },
      boxShadow: {
        'gold-sm': '0 0 8px rgba(201, 162, 39, 0.15)',
        'gold-md': '0 0 16px rgba(201, 162, 39, 0.2)',
        'gold-lg': '0 4px 24px rgba(201, 162, 39, 0.25)',
        'panel': '0 1px 3px rgba(0, 0, 0, 0.3), 0 1px 2px rgba(0, 0, 0, 0.2)',
        'panel-lg': '0 10px 40px rgba(0, 0, 0, 0.5)',
      },
      animation: {
        'fade-in': 'fadeIn 0.2s ease-out',
        'slide-up': 'slideUp 0.25s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
};
