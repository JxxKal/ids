/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        slate: {
          850: '#172033',
          950: '#0b1120',
        },
      },
    },
  },
};
