import React, { useState, useRef, useEffect } from 'react'
import { api } from '../../api/axios'
import {
  Sparkles,
  Bot,
  Send,
  X,
  Minimize2,
  Trash2,
  User,
  Shield,
  Zap,
  Check,
  Copy,
  ExternalLink,
  ChevronDown
} from 'lucide-react'
import { toast } from 'react-hot-toast'
import { ReportText } from '../ai/ReportText'
import { formatBkkTime } from '../../lib/time'

interface Message {
  id: string
  role: 'user' | 'model'
  content: string
  timestamp: string
}

const QUICK_PROMPTS = [
  'สรุปการโจมตี 24 ชั่วโมงล่าสุด',
  'IP ไหนควรบล็อก',
  'การโจมตีประเภทไหนเยอะสุด และควรทำอะไร',
  'URL ไหนถูกเล็งมากสุด',
]

// Answers come from this account's last 24 hours of logs only (api/copilot.py).
const INTRO = 'ถามเรื่องทราฟฟิกและการโจมตีของเว็บในบัญชีนี้ ข้อมูล 24 ชั่วโมงล่าสุด'

const now = () => formatBkkTime(new Date())

export const AICopilotWidget: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false)
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome-1',
      role: 'model',
      content: INTRO,
      timestamp: now(),
    },
  ])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    if (isOpen) {
      scrollToBottom()
    }
  }, [messages, isOpen])

  const handleSend = async (textToSend?: string) => {
    const messageText = (textToSend || input).trim()
    if (!messageText || isLoading) return

    const userMessage: Message = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: messageText,
      timestamp: formatBkkTime(new Date()),
    }

    setMessages((prev) => [...prev, userMessage])
    if (!textToSend) setInput('')
    setIsLoading(true)

    try {
      // Build history payload (the intro line is not part of the exchange)
      const historyPayload = messages.filter((m) => !m.id.startsWith('welcome')).map((m) => ({
        role: m.role,
        content: m.content,
      }))

      const response = await api.post('/copilot/chat', {
        message: messageText,
        history: historyPayload,
      })

      const botReply = response.data?.reply || 'ไม่มีคำตอบจากระบบ ลองใหม่อีกครั้ง'

      const botMessage: Message = {
        id: `bot-${Date.now()}`,
        role: 'model',
        content: botReply,
        timestamp: formatBkkTime(new Date()),
      }

      setMessages((prev) => [...prev, botMessage])
    } catch (error: any) {
      toast.error('ส่งคำถามไม่สำเร็จ')
      const errorMessage: Message = {
        id: `err-${Date.now()}`,
        role: 'model',
        content: 'เชื่อมต่อไม่สำเร็จ ลองใหม่อีกครั้ง',
        timestamp: formatBkkTime(new Date()),
      }
      setMessages((prev) => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    toast.success('คัดลอกแล้ว')
    setTimeout(() => setCopiedId(null), 2000)
  }

  const handleClear = () => {
    setMessages([
      {
        id: 'welcome-reset',
        role: 'model',
        content: INTRO,
        timestamp: now(),
      },
    ])
    toast.success('ล้างประวัติการสนทนาแล้ว')
  }

  return (
    <>
      {/* Floating Trigger Button */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 z-50 group flex items-center gap-2.5 px-4 py-3 rounded-full bg-gradient-to-r from-indigo-600 via-indigo-500 to-purple-600 text-white shadow-2xl hover:shadow-indigo-500/40 hover:scale-105 transition-all duration-300 border border-indigo-400/40 cursor-pointer"
        >
          <div className="relative">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 absolute -top-0.5 -right-0.5 animate-ping" />
            <span className="w-2 h-2 rounded-full bg-emerald-400 absolute -top-0 -right-0" />
            <Bot size={20} className="group-hover:rotate-12 transition-transform duration-300" />
          </div>
          <span className="font-mono text-[13px] font-bold tracking-tight">AI Copilot</span>
          <span className="px-1.5 py-0.5 rounded-full bg-white/20 text-[10px] font-mono uppercase tracking-wider font-bold">
            LIVE
          </span>
        </button>
      )}

      {/* Expanded Floating Chat Panel */}
      {isOpen && (
        <div className="fixed bottom-6 right-6 z-50 w-[92vw] sm:w-[420px] h-[580px] max-h-[85vh] bg-[var(--bg-surface)]/95 backdrop-blur-xl border border-indigo-500/30 rounded-2xl shadow-2xl flex flex-col overflow-hidden animate-in fade-in slide-in-from-bottom-5 duration-300">
          {/* Header */}
          <div className="px-4 py-3 bg-gradient-to-r from-indigo-950/80 via-slate-900/90 to-purple-950/80 border-b border-indigo-500/20 flex items-center justify-between shrink-0">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
                <Sparkles size={16} className="text-indigo-300" />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <h3 className="text-[13.5px] font-bold text-[var(--text-primary)] m-0 font-mono">
                    WAF Copilot
                  </h3>
                </div>
                <p className="text-[10.5px] text-[var(--text-muted)] m-0 flex items-center gap-1 mt-0.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block" />
                  <span>ข้อมูล 24 ชม. ของเว็บในบัญชีนี้</span>
                </p>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <button
                onClick={handleClear}
                className="p-1.5 rounded-lg text-[var(--text-muted)] hover:text-red-400 hover:bg-white/5 transition-colors cursor-pointer"
                title="Clear Chat"
              >
                <Trash2 size={14} />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-white/5 transition-colors cursor-pointer"
                title="Close"
              >
                <Minimize2 size={14} />
              </button>
            </div>
          </div>

          {/* Chat Messages Stream */}
          <div className="flex-1 p-4 overflow-y-auto space-y-3.5 font-sans">
            {messages.map((msg) => {
              const isBot = msg.role === 'model'
              return (
                <div
                  key={msg.id}
                  className={`flex gap-2.5 ${isBot ? 'items-start' : 'items-end justify-end'}`}
                >
                  {isBot && (
                    <div className="w-7 h-7 rounded-lg bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 shrink-0 mt-0.5">
                      <Bot size={15} />
                    </div>
                  )}

                  <div
                    className={`max-w-[85%] rounded-2xl p-3 text-[12.5px] leading-relaxed relative group ${
                      isBot
                        ? 'bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] text-[var(--text-primary)]'
                        : 'bg-indigo-600 text-white rounded-br-none shadow-md'
                    }`}
                  >
                    <div className="space-y-1">
                      {isBot ? <ReportText text={msg.content} className="text-[12px]" /> : msg.content}
                    </div>

                    <div className="flex items-center justify-between gap-2 mt-2 pt-1 border-t border-white/5 text-[10px] text-[var(--text-muted)] font-mono">
                      <span>{msg.timestamp}</span>
                      {isBot && (
                        <button
                          onClick={() => handleCopy(msg.content, msg.id)}
                          className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-indigo-400 cursor-pointer"
                          title="Copy response"
                        >
                          {copiedId === msg.id ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                        </button>
                      )}
                    </div>
                  </div>

                  {!isBot && (
                    <div className="w-7 h-7 rounded-lg bg-purple-500/20 border border-purple-500/30 flex items-center justify-center text-purple-400 shrink-0 mb-0.5">
                      <User size={15} />
                    </div>
                  )}
                </div>
              )
            })}

            {/* Loading Indicator */}
            {isLoading && (
              <div className="flex items-center gap-2.5 text-[12px] text-indigo-400 font-mono bg-indigo-500/10 p-2.5 rounded-xl border border-indigo-500/20 w-fit">
                <Sparkles size={14} className="animate-spin text-indigo-400" />
                <span>Copilot กำลังวิเคราะห์ข้อมูลสดจาก ClickHouse...</span>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick Starter Chips */}
          <div className="px-3 py-2 border-t border-[var(--bg-border-subtle)] bg-[var(--bg-surface-elevated)] flex gap-1.5 overflow-x-auto no-scrollbar">
            {QUICK_PROMPTS.map((prompt, idx) => (
              <button
                key={idx}
                onClick={() => handleSend(prompt)}
                disabled={isLoading}
                className="px-2.5 py-1 rounded-full text-[11px] font-mono text-[var(--text-secondary)] hover:text-indigo-300 hover:bg-indigo-500/10 border border-[var(--bg-border)] hover:border-indigo-500/30 shrink-0 transition-all cursor-pointer disabled:opacity-50"
              >
                {prompt}
              </button>
            ))}
          </div>

          {/* Input Box */}
          <div className="p-3 bg-[var(--bg-surface)] border-t border-[var(--bg-border)] flex items-center gap-2">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
              placeholder="ถามข้อมูลความปลอดภัย เช่น 'IP ไหนโจมตีบ่อยสุด'..."
              disabled={isLoading}
              className="flex-1 px-3.5 py-2 rounded-xl bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] text-[12.5px] text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-indigo-500 font-sans"
            />
            <button
              onClick={() => handleSend()}
              disabled={!input.trim() || isLoading}
              className="p-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white transition-all disabled:opacity-40 shadow-md cursor-pointer shrink-0"
            >
              <Send size={15} />
            </button>
          </div>
        </div>
      )}
    </>
  )
}
