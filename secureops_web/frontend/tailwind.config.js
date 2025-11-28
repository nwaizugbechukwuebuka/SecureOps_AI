module.exports = {
  content: [
    "./src/**/*.{js,ts,jsx,tsx}",
    "./src/components/ui/**/*.{js,ts,jsx,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        primary: '#0f172a',
        accent: '#38bdf8',
        danger: '#ef4444',
        success: '#22c55e',
        warning: '#facc15',
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
}
