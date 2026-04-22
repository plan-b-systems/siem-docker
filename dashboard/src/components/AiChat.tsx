'use client'

import { useState, useRef, useEffect } from 'react'
import { useLanguage } from './LanguageProvider'
import { Bot, Send, Loader2, X, Plus, Cpu } from 'lucide-react'
import { cn } from '@/lib/utils'

interface Message {
  role: 'user' | 'assistant'
  content: string
  model?: string
  suggestions?: string[]
  result_count?: number | null
}

const QUICK_PROMPTS_HE = [
  { label: 'סיכום אבטחה', prompt: 'תן לי סיכום אבטחה של 24 השעות האחרונות' },
  { label: 'כניסות כושלות', prompt: 'הראה לי את כל ניסיונות הכניסה הכושלים' },
  { label: 'התראות קריטיות', prompt: 'מה ההתראות הקריטיות האחרונות?' },
  { label: 'פעילות חריגה', prompt: 'האם יש פעילות חריגה בלוגים?' },
  { label: 'מכשירים פעילים', prompt: 'אילו מכשירים שולחים לוגים?' },
]

const QUICK_PROMPTS_EN = [
  { label: 'Security Summary', prompt: 'Give me a security summary of the last 24 hours' },
  { label: 'Failed Logins', prompt: 'Show me all failed login attempts' },
  { label: 'Critical Alerts', prompt: 'What are the latest critical alerts?' },
  { label: 'Anomalies', prompt: 'Is there any anomalous activity in the logs?' },
  { label: 'Active Devices', prompt: 'Which devices are sending logs?' },
]

export default function AiChat() {
  const { locale } = useLanguage()
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [error, setError] = useState('')
  const scrollRef = useRef<HTMLDivElement>(null)

  const quickPrompts = locale === 'he' ? QUICK_PROMPTS_HE : QUICK_PROMPTS_EN

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [messages, loading])

  async function sendMessage(text: string) {
    if (!text.trim() || loading) return
    setError('')

    const userMsg: Message = { role: 'user', content: text }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const res = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, session_id: sessionId }),
      })

      if (!res.ok) {
        const data = await res.json()
        setError(data.error || 'AI service error')
        setLoading(false)
        return
      }

      const data = await res.json()
      setSessionId(data.session_id)
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.message,
        model: data.model,
        suggestions: data.suggestions,
        result_count: data.result_count,
      }])
    } catch {
      setError('Connection error')
    }
    setLoading(false)
  }

  function newSession() {
    setMessages([])
    setSessionId(null)
    setError('')
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="fixed bottom-6 right-80 z-50 w-14 h-14 rounded-full bg-blue-600 hover:bg-blue-500 text-white shadow-lg flex items-center justify-center transition-transform hover:scale-105"
        title="AI Assistant"
      >
        <Bot size={24} />
      </button>
    )
  }

  return (
    <div className="fixed bottom-6 right-80 z-50 w-[480px] h-[600px] bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 bg-slate-900">
        <div className="flex items-center gap-2">
          <Bot size={18} className="text-blue-400" />
          <span className="text-sm font-medium text-white">Plan-B AI Assistant</span>
        </div>
        <div className="flex items-center gap-1">
          <button onClick={newSession} className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white" title="New session">
            <Plus size={16} />
          </button>
          <button onClick={() => setOpen(false)} className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white">
            <X size={16} />
          </button>
        </div>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
        {messages.length === 0 && (
          <div className="space-y-3 pt-4">
            <p className="text-sm text-slate-400 text-center">
              {locale === 'he' ? 'שאל על לוגים, איומים, או אירועי אבטחה' : 'Ask about logs, threats, or security events'}
            </p>
            <div className="flex flex-wrap gap-2 justify-center">
              {quickPrompts.map((q, i) => (
                <button
                  key={i}
                  onClick={() => sendMessage(q.prompt)}
                  className="px-3 py-1.5 text-xs rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
                >
                  {q.label}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={cn('flex min-w-0', msg.role === 'user' ? 'justify-end' : 'justify-start')}>
            <div className={cn(
              'max-w-[85%] min-w-0 rounded-xl px-3.5 py-2.5 text-sm',
              'overflow-hidden',
              msg.role === 'user'
                ? 'bg-blue-600 text-white'
                : 'bg-slate-800 text-slate-200'
            )}>
              {msg.role === 'assistant' && msg.model && (
                <div className="flex items-center gap-1 mb-1 text-[10px] text-slate-500">
                  <Cpu size={10} /> {msg.model}
                  {msg.result_count !== null && msg.result_count !== undefined && (
                    <span className="ml-2">{msg.result_count} results</span>
                  )}
                </div>
              )}
              {/* break-words handles normal text; [overflow-wrap:anywhere] breaks long tokens
                  (paths, IPs, hashes) mid-string so they can't blow out the 85% bubble width */}
              <div className="whitespace-pre-wrap break-words [overflow-wrap:anywhere]">{msg.content}</div>
              {msg.suggestions && msg.suggestions.length > 0 && (
                <div className="flex flex-wrap gap-1.5 mt-2 pt-2 border-t border-slate-700">
                  {msg.suggestions.map((s, j) => (
                    <button
                      key={j}
                      onClick={() => sendMessage(s)}
                      className="px-2 py-1 text-[10px] rounded bg-slate-700 text-slate-300 hover:bg-slate-600 hover:text-white transition-colors"
                    >
                      {s}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div className="bg-slate-800 rounded-xl px-4 py-3">
              <Loader2 size={16} className="animate-spin text-blue-400" />
            </div>
          </div>
        )}

        {error && (
          <div className="text-center text-xs text-red-400 bg-red-500/10 rounded-lg py-2">{error}</div>
        )}
      </div>

      {/* Input */}
      <div className="border-t border-slate-800 p-3">
        <form
          onSubmit={(e) => { e.preventDefault(); sendMessage(input) }}
          className="flex gap-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={locale === 'he' ? 'שאל על הלוגים...' : 'Ask about the logs...'}
            className="flex-1 h-10 px-3 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="h-10 w-10 rounded-lg bg-blue-600 hover:bg-blue-500 text-white flex items-center justify-center disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            <Send size={16} />
          </button>
        </form>
      </div>
    </div>
  )
}
