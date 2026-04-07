'use client'

import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { type Locale, type TranslationKey, t as translate, getDirection } from '@/lib/i18n'

interface LanguageContextType {
  locale: Locale
  setLocale: (locale: Locale) => void
  t: (key: TranslationKey) => string
  dir: 'rtl' | 'ltr'
}

const LanguageContext = createContext<LanguageContextType>({
  locale: 'he',
  setLocale: () => {},
  t: (key) => key,
  dir: 'rtl',
})

export function useLanguage() {
  return useContext(LanguageContext)
}

export function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>('he')

  useEffect(() => {
    const saved = localStorage.getItem('plansb_locale') as Locale | null
    if (saved === 'he' || saved === 'en') {
      setLocaleState(saved)
    }
  }, [])

  const setLocale = useCallback((newLocale: Locale) => {
    setLocaleState(newLocale)
    localStorage.setItem('plansb_locale', newLocale)
    document.documentElement.lang = newLocale
    document.documentElement.dir = getDirection(newLocale)
  }, [])

  const t = useCallback((key: TranslationKey) => translate(key, locale), [locale])
  const dir = getDirection(locale)

  useEffect(() => {
    document.documentElement.lang = locale
    document.documentElement.dir = dir
  }, [locale, dir])

  return (
    <LanguageContext.Provider value={{ locale, setLocale, t, dir }}>
      {children}
    </LanguageContext.Provider>
  )
}
