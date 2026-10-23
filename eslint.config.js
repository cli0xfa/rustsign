import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import prettier from 'eslint-config-prettier';

export default tseslint.config(
  // Generated artefacts and non-frontend code are not linted here.
  { ignores: ['dist', 'build', 'node_modules', 'src-tauri'] },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    files: ['src/**/*.{ts,tsx}'],
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    languageOptions: {
      parserOptions: {
        ecmaVersion: 2021,
        sourceType: 'module',
        ecmaFeatures: { jsx: true },
      },
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // `set-state-in-effect` flags the common "load data on mount" pattern
      // (e.g. `useEffect(() => refresh(), [])`). That pattern is intentional
      // across the data hooks here, so disable the rule rather than refactor
      // every call site.
      'react-hooks/set-state-in-effect': 'off',
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
    },
  },

  // Disable stylistic rules that conflict with Prettier.
  prettier,
);
