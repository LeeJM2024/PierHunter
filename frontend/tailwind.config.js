/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        soc: {
          indigo: "#4f46e5",
          "indigo-light": "#6366f1",
          "cyber-green": "#22c55e", // 赛博绿 #22c55e
          "cyber-green-glow": "rgba(34, 197, 94, 0.3)",
          "alert-rose": "#f43f5e", // 警报红 #f43f5e
          "critical-amber": "#f59e0b", // 高危橙 #f59e0b
          emerald: "#10b981",
          cyan: "#06b6d4",
          "cyan-glow": "rgba(6, 182, 212, 0.3)",
          "electric-blue": "#3b82f6",
          "electric-purple": "#8b5cf6",
        },
        // 深度暗色主题调色板
        "deep-dark": {
          900: "#0f172a", // slate-900
          950: "#020617", // gray-950
          975: "#01050f", // 更深
        },
      },
      backgroundImage: {
        "soc-gradient": "linear-gradient(135deg, #4f46e5 0%, #3b82f6 50%, #06b6d4 100%)",
        "cyber-gradient": "linear-gradient(135deg, #22c55e 0%, #06b6d4 50%, #3b82f6 100%)",
        "amber-gradient": "linear-gradient(135deg, #f59e0b 0%, #f43f5e 100%)",
        "emerald-gradient": "linear-gradient(135deg, #10b981 0%, #06b6d4 100%)",
        // 极深邃蓝黑渐变
        "deep-dark-gradient": "linear-gradient(135deg, #0f172a 0%, #020617 50%, #01050f 100%)",
        "cyber-dark-gradient": "radial-gradient(circle at 50% 0%, #0f172a 0%, #020617 70%, #01050f 100%)",
      },
      boxShadow: {
        neon: "0 0 0 1px rgba(34,211,238,.3), 0 0 40px rgba(14,116,144,.25)",
        "soc-glow": "0 0 20px rgba(79, 70, 229, 0.4), 0 0 40px rgba(79, 70, 229, 0.2)",
        "cyber-glow": "0 0 20px rgba(16, 185, 129, 0.4), 0 0 40px rgba(16, 185, 129, 0.2)",
        "amber-glow": "0 0 20px rgba(245, 158, 11, 0.4), 0 0 40px rgba(245, 158, 11, 0.2)",
        "rose-glow": "0 0 20px rgba(239, 68, 68, 0.4), 0 0 40px rgba(239, 68, 68, 0.2)",
      },
      keyframes: {
        "terminal-fade": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-glow": {
          "0%, 100%": { boxShadow: "0 0 20px rgba(79, 70, 229, 0.4), 0 0 40px rgba(79, 70, 229, 0.2)" },
          "50%": { boxShadow: "0 0 30px rgba(79, 70, 229, 0.6), 0 0 60px rgba(79, 70, 229, 0.3)" },
        },
        "cyber-pulse": {
          "0%, 100%": { boxShadow: "0 0 20px rgba(16, 185, 129, 0.4), 0 0 40px rgba(16, 185, 129, 0.2)" },
          "50%": { boxShadow: "0 0 30px rgba(16, 185, 129, 0.6), 0 0 60px rgba(16, 185, 129, 0.3)" },
        },
        "breathing": {
          "0%, 100%": { opacity: "0.9" },
          "50%": { opacity: "1" },
        },
        "danger-pulse": {
          "0%, 100%": { opacity: "0.9", boxShadow: "0 0 0 0 rgba(239, 68, 68, 0.4)" },
          "50%": { opacity: "1", boxShadow: "0 0 0 4px rgba(239, 68, 68, 0.2)" },
        },
      },
      animation: {
        "terminal-fade": "terminal-fade .35s ease-out",
        "pulse-glow": "pulse-glow 2s ease-in-out infinite",
        "cyber-pulse": "cyber-pulse 2s ease-in-out infinite",
        "breathing": "breathing 2s ease-in-out infinite",
        "danger-pulse": "danger-pulse 1.5s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
