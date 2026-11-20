/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#050811",
          panel: "#0B1120",
          card: "#11192C",
          border: "#1E293B",
          cyan: "#06B6D4",
          emerald: "#10B981",
          amber: "#F59E0B",
          crimson: "#EF4444",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
    },
  },
  plugins: [],
};
