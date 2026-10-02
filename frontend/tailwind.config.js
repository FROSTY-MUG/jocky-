/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#080c14",
          card: "#0d1424",
          cardHover: "#121b30",
          border: "#1f293d",
          cyan: "#06b6d4",
          cyanGlow: "rgba(6, 182, 212, 0.15)",
          emerald: "#10b981",
          emeraldGlow: "rgba(16, 185, 129, 0.15)",
          rose: "#f43f5e",
          roseGlow: "rgba(244, 63, 94, 0.15)",
          indigo: "#6366f1",
          indigoGlow: "rgba(99, 102, 241, 0.15)",
          amber: "#f59e0b",
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      animation: {
        'pulse-subtle': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      }
    },
  },
  plugins: [],
}
