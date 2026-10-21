// Tailwind config for the proxpass admin UI.
//
// Theme (primary/secondary colors, @tailwindcss/forms, the custom-scrollbar
// utility) is taken from the TailwindCSS-Alpine.js-Template this UI is based
// on: https://github.com/vojislavd/TailwindCSS-Alpine.js-Template
//
// Compiled by the mise-pinned Tailwind standalone CLI (no Node.js). The forms
// plugin is bundled into that binary, so `require('@tailwindcss/forms')' works
// without a node_modules install. `content' is scanned for class names, so the
// minified output contains only the classes index.html actually uses.
const plugin = require('tailwindcss/plugin');

module.exports = {
  content: ['./index.html'],
  theme: {
    extend: {
      colors: {
        primary: '#1f4b8e',
        'primary-dark': '#102a52',
        secondary: '#182430',
        'secondary-dark': '#060C11',
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    plugin(function ({ addUtilities }) {
      addUtilities(
        {
          '.custom-scrollbar::-webkit-scrollbar': { width: '6px', height: '6px' },
          '.custom-scrollbar::-webkit-scrollbar-track': { background: 'transparent' },
          '.custom-scrollbar::-webkit-scrollbar-thumb': { background: '#888', borderRadius: '3px' },
          '.custom-scrollbar::-webkit-scrollbar-thumb:hover': { background: '#555' },
        },
        ['responsive', 'hover'],
      );
    }),
  ],
};
