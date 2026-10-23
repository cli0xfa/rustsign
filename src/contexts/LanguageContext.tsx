import { createContext, useContext, useEffect, useState, useCallback } from 'react';
import type { Language } from '@/types';
import { STORAGE_KEYS } from '@/lib/constants';
import { t as translate } from '@/i18n/translations';

interface LanguageContextValue {
  language: Language;
  setLanguage: (l: Language) => void;
  toggle: () => void;
  t: (key: string, vars?: Record<string, string | number>) => string;
}

const LanguageContext = createContext<LanguageContextValue | null>(null);

function readStoredLanguage(): Language {
  try {
    return localStorage.getItem(STORAGE_KEYS.language) === 'en' ? 'en' : 'zh-CN';
  } catch {
    return 'zh-CN';
  }
}

export function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [language, setLanguageState] = useState<Language>(readStoredLanguage);

  useEffect(() => {
    document.documentElement.lang = language === 'en' ? 'en' : 'zh-CN';
  }, [language]);

  const setLanguage = useCallback((l: Language) => {
    setLanguageState(l);
    try {
      localStorage.setItem(STORAGE_KEYS.language, l);
    } catch {
      /* ignore */
    }
  }, []);

  const toggle = useCallback(() => {
    setLanguage(language === 'zh-CN' ? 'en' : 'zh-CN');
  }, [language, setLanguage]);

  const t = useCallback(
    (key: string, vars?: Record<string, string | number>) => translate(key, language, vars),
    [language],
  );

  return (
    <LanguageContext.Provider value={{ language, setLanguage, toggle, t }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage(): LanguageContextValue {
  const ctx = useContext(LanguageContext);
  if (!ctx) throw new Error('useLanguage must be used within LanguageProvider');
  return ctx;
}
