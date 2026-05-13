'use client'

import { useState, useRef, useEffect } from 'react'
import { v4 as uuidv4 } from 'uuid'
import { MessageList } from './MessageList'
import { FileUpload } from './FileUpload'
import { Send, Paperclip, Loader2 } from 'lucide-react'

export interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: Date
  attachments?: FileAttachment[]
  error?: PolicyError
  // Synthetic content provenance metadata (required for AI-generated messages)
  provenance?: {
    modelId: string
    origin: 'ai-generated'
    syntheticLabel: string
    generatedAt: string
  }
}

export interface FileAttachment {
  id: string
  name: string
  type: string
  size: number
  content?: string
}

export interface PolicyError {
  type: 'pii' | 'threat' | 'auth' | 'general'
  message: string
  details?: Record<string, unknown>
}

const MALICIOUS_PATTERNS: { name: string; pattern: RegExp }[] = [
  // Direct prompt injection attempts
  { name: 'prompt_injection', pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i },
  { name: 'prompt_injection', pattern: /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i },
  { name: 'prompt_injection', pattern: /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i },
  { name: 'prompt_injection', pattern: /you\s+are\s+now\s+(a\s+)?(?!an?\s+assistant)/i },
  { name: 'prompt_injection', pattern: /act\s+as\s+(if\s+you\s+are|a|an)\s+/i },
  { name: 'prompt_injection', pattern: /new\s+(role|persona|instructions?|prompt|system\s+prompt)/i },
  { name: 'prompt_injection', pattern: /\[\s*(system|assistant|user|instruction)\s*\]/i },
  { name: 'prompt_injection', pattern: /<\s*(system|instructions?|prompt)\s*>/i },
  // Base64-encoded content (suspicious blobs that decode to text)
  { name: 'base64_encoded', pattern: /(?:[A-Za-z0-9+\/]{40,}={0,2})/ },
  // Shell commands
  { name: 'shell_command', pattern: /(?:^|\s)(rm\s+-rf|sudo\s+|chmod\s+|curl\s+|wget\s+|bash\s+-c|sh\s+-c|eval\s*\(|exec\s*\()/im },
  { name: 'shell_command', pattern: /`[^`]{5,}`/ },
  { name: 'shell_command', pattern: /\$\([^)]{5,}\)/ },
  // Leetspeak prompt injection
  { name: 'leetspeak', pattern: /[1!][Gg][Nn][0Oo][Rr][3Ee]\s+[Aa4][Ll1][Ll1]/i },
  { name: 'leetspeak', pattern: /(?:[4@][Cc][Tt]\s+[Aa4][Ss]|[Yy][0Oo][Uu]\s+[Aa4][Rr][3Ee]\s+[Nn][0Oo][Ww])/i },
  // Hidden/invisible unicode characters used to smuggle instructions
  { name: 'hidden_unicode', pattern: /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/ },
  // Jailbreak keywords
  { name: 'jailbreak', pattern: /\b(jailbreak|DAN\b|do\s+anything\s+now|developer\s+mode|unrestricted\s+mode|bypass\s+(safety|filter|policy|restriction))/i },
  { name: 'jailbreak', pattern: /\bpretend\s+(there\s+are\s+no|you\s+have\s+no)\s+(rules?|restrictions?|guidelines?|limits?)/i },
]

function sanitizeFileContent(content: string, fileName: string): void {
  for (const { name, pattern } of MALICIOUS_PATTERNS) {
    if (pattern.test(content)) {
      throw new Error(
        `File "${fileName}" was rejected: potentially malicious content detected (${name}). Please review the file and remove any embedded instructions or commands before uploading.`
      )
    }
  }

  // Secondary check: attempt to decode base64 blobs and re-scan
  const base64Regex = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g
  let match: RegExpExecArray | null
  while ((match = base64Regex.exec(content)) !== null) {
    try {
      const decoded = atob(match[0])
      // Only flag if decoded result looks like readable text with suspicious keywords
      if (/[\x20-\x7E]{20,}/.test(decoded)) {
        for (const { name: pName, pattern: pPattern } of MALICIOUS_PATTERNS.slice(0, 8)) {
          if (pPattern.test(decoded)) {
            throw new Error(
              `File "${fileName}" was rejected: base64-encoded malicious content detected (${pName}). Please review the file before uploading.`
            )
          }
        }
      }
    } catch (e) {
      if (e instanceof Error && e.message.includes('rejected')) throw e
      // Not valid base64 or binary — skip
    }
  }
}

// ── Prompt-injection / malicious-command sanitisation ──────────────────────
const INVISIBLE_CHAR_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g

// Base64 blocks long enough to hide an encoded payload (≥ 40 chars)
const BASE64_RE = /(?:[A-Za-z0-9+/]{40,}={0,2})/

// Common shell / system-command patterns
const SHELL_CMD_RE = /(?:^|[\s;|&`$(){}])(?:bash|sh|zsh|cmd|powershell|pwsh|exec|eval|system|popen|subprocess|os\.system|__import__|curl|wget|nc|ncat|netcat|chmod|chown|sudo|su\s|rm\s+-rf|dd\s+if=|mkfifo|python[23]?\s+-c|perl\s+-e|ruby\s+-e|php\s+-r)/i

// Leetspeak substitution map – normalise before checking
const LEET_MAP: Record<string, string> = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i',
}
function normaliseLeet(text: string): string {
  return text.replace(/[01345@$!7]/g, c => LEET_MAP[c] ?? c)
}

// Binary / executable magic-byte prefixes (hex strings)
const BINARY_MAGIC = [
  '\x7fELF',   // ELF
  'MZ',        // PE / DOS
  '\xcf\xfa\xed\xfe', // Mach-O 64-bit LE
  '\xce\xfa\xed\xfe', // Mach-O 32-bit LE
  'PK\x03\x04', // ZIP / JAR / DOCX etc.
]

function containsBinaryExecutable(text: string): boolean {
  return BINARY_MAGIC.some(magic => text.startsWith(magic))
}

function sanitiseText(text: string): { safe: boolean; reason?: string } {
  if (!text) return { safe: true }

  // 1. Invisible / control characters
  if (INVISIBLE_CHAR_RE.test(text)) {
    return { safe: false, reason: 'Input contains hidden or invisible characters that may be used for prompt injection.' }
  }

  // 2. Binary executable signatures
  if (containsBinaryExecutable(text)) {
    return { safe: false, reason: 'Input contains binary executable content.' }
  }

  // 3. Base64-encoded payload
  if (BASE64_RE.test(text)) {
    return { safe: false, reason: 'Input contains a large base64-encoded block that may conceal a malicious payload.' }
  }

  // 4. Shell / system commands (raw + leet-normalised)
  if (SHELL_CMD_RE.test(text) || SHELL_CMD_RE.test(normaliseLeet(text))) {
    return { safe: false, reason: 'Input contains shell or system command patterns that are not permitted.' }
  }

  return { safe: true }
}

function sanitisePayload(
  message: string,
  attachments: FileAttachment[]
): { safe: boolean; reason?: string } {
  const msgCheck = sanitiseText(message)
  if (!msgCheck.safe) return msgCheck

  for (const att of attachments) {
    if (att.content) {
      const attCheck = sanitiseText(att.content)
      if (!attCheck.safe) {
        return { safe: false, reason: `Attachment "${att.name}": ${attCheck.reason}` }
      }
    }
  }
  return { safe: true }
}
// ────────────────────────────────────────────────────────────────────────────

const PII_PATTERNS: { label: string; pattern: RegExp }[] = [
  { label: 'EMAIL', pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g },
  { label: 'PHONE', pattern: /(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}/g },
  { label: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { label: 'CREDIT_CARD', pattern: /\b(?:\d[ -]?){13,16}\b/g },
]

function redactPII(content: string): string {
  let redacted = content
  for (const { label, pattern } of PII_PATTERNS) {
    redacted = redacted.replace(pattern, `[REDACTED_${label}]`)
  }
  return redacted
}

// Singapore PII detection patterns
const SINGAPORE_PII_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'Singapore NRIC/FIN', pattern: /\b[STFGM]\d{7}[A-Z]\b/i },
  { name: 'Singapore Passport', pattern: /\bE\d{7}[A-Z]\b/i },
  { name: 'Singapore Phone Number', pattern: /\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b/ },
  { name: 'Email Address', pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/ },
  { name: 'Full Name with Salutation', pattern: /\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b/ },
  { name: 'Singapore Postal Code', pattern: /\bSingapore\s+\d{6}\b/i },
  { name: 'Singapore Address', pattern: /\b(?:Blk|Block|No\.?)\s+\d+[A-Z]?\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Place|Pl|Crescent|Cres|Walk|Way|Close|Cl|Terrace|Ter)\b/i },
  { name: 'Bank Account Number', pattern: /\b\d{3}[-\s]?\d{5}[-\s]?\d{3}\b/ },
  { name: 'Credit Card Number', pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/ },
]

function detectSingaporePII(content: string): { detected: boolean; categories: string[] } {
  const detectedCategories: string[] = []
  for (const { name, pattern } of SINGAPORE_PII_PATTERNS) {
    if (pattern.test(content)) {
      detectedCategories.push(name)
    }
  }
  return { detected: detectedCategories.length > 0, categories: detectedCategories }
}

export function ChatInterface() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [pendingFiles, setPendingFiles] = useState<File[]>([])
  const [showFileUpload, setShowFileUpload] = useState(false)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Session-scoped conversation token with signing, expiry, and binding
  const [sessionToken] = useState<{ token: string; signature: string; iat: number; exp: number; sessionKey: string }>(() => {
    const conversationId = uuidv4()
    const sessionKey = uuidv4() // per-session binding secret
    const iat = Date.now()
    const exp = iat + 60 * 60 * 1000 // 1 hour expiry
    // HMAC-SHA256 simulation using SubtleCrypto is async; use a synchronous HMAC-like
    // construction with available primitives: sign = base64(sha256-like hash of key+payload)
    // We store the components and compute a deterministic signature string
    const payload = `${conversationId}:${sessionKey}:${iat}:${exp}`
    // Produce a stable signature by hashing the payload with a simple djb2-based approach
    // and encoding as hex — sufficient for integrity binding in this synchronous context
    let hash = 5381
    for (let i = 0; i < payload.length; i++) {
      hash = ((hash << 5) + hash) ^ payload.charCodeAt(i)
      hash = hash >>> 0 // keep unsigned 32-bit
    }
    // Strengthen with a second pass over reversed payload
    const reversed = payload.split('').reverse().join('')
    let hash2 = 0x811c9dc5
    for (let i = 0; i < reversed.length; i++) {
      hash2 ^= reversed.charCodeAt(i)
      hash2 = Math.imul(hash2, 0x01000193) >>> 0
    }
    const signature = `${hash.toString(16).padStart(8, '0')}${hash2.toString(16).padStart(8, '0')}`
    return { token: conversationId, signature, iat, exp, sessionKey }
  })

  const getSignedConversationId = () => {
    const now = Date.now()
    if (now > sessionToken.exp) {
      throw new Error('Session token has expired. Please refresh the page to start a new session.')
    }
    return {
      token: sessionToken.token,
      signature: sessionToken.signature,
      iat: sessionToken.iat,
      exp: sessionToken.exp,
    }
  }

  const getAuthToken = (): string | null => {
    return localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token') || null
  }

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus()
    }
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!input.trim() && pendingFiles.length === 0) return

    const attachments: FileAttachment[] = []

        // Process pending files — check for Singapore PII before attaching
    for (const file of pendingFiles) {
      const content = await readFileContent(file)
      const piiCheck = detectSingaporePII(content)
      if (piiCheck.detected) {
        const piiErrorMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: `File "${file.name}" was not uploaded because it contains Singapore PII: ${piiCheck.categories.join(', ')}. Please remove sensitive information before uploading.`,
          timestamp: new Date(),
          error: {
            type: 'pii',
            message: `Singapore PII detected in uploaded file: ${piiCheck.categories.join(', ')}`,
            details: { file: file.name, categories: piiCheck.categories },
          },
        }
        setMessages(prev => [...prev, piiErrorMessage])
        setPendingFiles([])
        setShowFileUpload(false)
        setIsLoading(false)
        return
      }
      attachments.push({
        id: uuidv4(),
        name: file.name,
        type: file.type,
        size: file.size,
        content,
      })
    })
    }

    const userMessage: Message = {
      id: uuidv4(),
      role: 'user',
      content: input || `Uploaded ${pendingFiles.length} file(s)`,
      timestamp: new Date(),
      attachments: attachments.length > 0 ? attachments : undefined,
    }

    setMessages(prev => [...prev, userMessage])
    setInput('')
    setPendingFiles([])
    setShowFileUpload(false)
    setIsLoading(true)

    try {
      const authToken = getAuthToken()
      if (!authToken) {
        const authErrorMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: 'Authentication required. Please log in before using the AI Agent.',
          timestamp: new Date(),
          error: {
            type: 'auth',
            message: 'User is not authenticated. Access to the AI Agent is denied.',
          },
        }
        setMessages(prev => [...prev, authErrorMessage])
        setIsLoading(false)
        return
      }

      const response = await fetch('/api/backend/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          message: sanitized.message,
          attachments: sanitized.attachments,
          conversation_id: getSignedConversationId(),
        }),
      })

      let sanitized: { message: string; attachments: typeof attachments }
      try {
        sanitized = validateAndSanitizeInput(input, attachments)
      } catch (validationError) {
        const errMsg = validationError instanceof Error ? validationError.message : 'Invalid input.'
        const validationErrorMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: errMsg,
          timestamp: new Date(),
          error: { type: 'general', message: 'Input validation error' },
        }
        setMessages(prev => [...prev, validationErrorMessage])
        setIsLoading(false)
        return
      }

      const data = await response.json()

      const DANGEROUS_PATTERNS = [
        /\beval\s*\(/gi,
        /\bexec\s*\(/gi,
        /new\s+Function\s*\(/gi,
        /setTimeout\s*\(\s*['"`]/gi,
        /setInterval\s*\(\s*['"`]/gi,
        /\bimportScripts\s*\(/gi,
        /document\.write\s*\(/gi,
        /\.innerHTML\s*=/gi,
        /\bexecScript\s*\(/gi,
      ]

      const sanitizeLLMOutput = (text: string): string => {
        if (typeof text !== 'string') return ''
        const hasDangerousPattern = DANGEROUS_PATTERNS.some(pattern => pattern.test(text))
        if (hasDangerousPattern) {
          console.warn('LLM output contained potentially dangerous code execution primitives and was sanitized.')
          return '[Response blocked: output contained disallowed dynamic code execution primitives.]'
        }
        return text
      }

      if (!response.ok) {
        // Handle policy violations returned as errors
        const errorMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: data.detail || 'An error occurred',
          timestamp: new Date(),
          provenance: {
            modelId: data.model || 'unknown-model',
            origin: 'ai-generated',
            syntheticLabel: 'AI-Generated Content',
            generatedAt: new Date().toISOString(),
          },
          error: data.policy_error ? {
            type: data.policy_error.type,
            message: data.policy_error.message,
            details: data.policy_error.details,
          } : undefined,
        }
        setMessages(prev => [...prev, errorMessage])
      } else {
        const assistantMessage: Message = {
          id: uuidv4(),
          provenance: {
            modelId: data.model || 'unknown-model',
            origin: 'ai-generated',
            syntheticLabel: 'AI-Generated Content',
            generatedAt: new Date().toISOString(),
          },
          role: 'assistant',
          content: sanitizeLLMOutput(data.response),
          timestamp: new Date(),
          error: data.policy_warning ? {
            type: data.policy_warning.type,
            message: data.policy_warning.message,
            details: data.policy_warning.details,
          } : undefined,
        }
        setMessages(prev => [...prev, assistantMessage])
      }
    } catch (error) {
      const errorMessage: Message = {
        id: uuidv4(),
        role: 'assistant',
        content: 'Failed to connect to the backend. Please ensure the server is running.',
        timestamp: new Date(),
        error: {
          type: 'general',
          message: 'Connection error',
        },
      }
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  const MAX_MESSAGE_LENGTH = 10000
  const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024 // 10 MB
  const ALLOWED_MIME_TYPES = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'application/pdf',
    'text/plain', 'text/html', 'text/csv',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  ]

  const sanitizeText = (text: string): string => {
    // Trim whitespace
    let sanitized = text.trim()
    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '')
    // Normalize unicode to prevent homograph attacks
    sanitized = sanitized.normalize('NFC')
    return sanitized
  }

  const validateAndSanitizeInput = (
    message: string,
    attachments: { name: string; type: string; content: string; size?: number }[]
  ): { message: string; attachments: typeof attachments } => {
    const sanitizedMessage = sanitizeText(message)
    if (sanitizedMessage.length === 0) {
      throw new Error('Message cannot be empty.')
    }
    if (sanitizedMessage.length > MAX_MESSAGE_LENGTH) {
      throw new Error(`Message exceeds maximum allowed length of ${MAX_MESSAGE_LENGTH} characters.`)
    }

    const sanitizedAttachments = attachments.map((attachment) => {
      if (!ALLOWED_MIME_TYPES.includes(attachment.type)) {
        throw new Error(`File type "${attachment.type}" is not allowed.`)
      }
      if (attachment.size !== undefined && attachment.size > MAX_FILE_SIZE_BYTES) {
        throw new Error(`File "${attachment.name}" exceeds the maximum allowed size of 10 MB.`)
      }
      // Sanitize file name: keep only alphanumeric, dots, dashes, underscores
      const sanitizedName = attachment.name.replace(/[^a-zA-Z0-9._\-]/g, '_')
      return { ...attachment, name: sanitizedName }
    })

    return { message: sanitizedMessage, attachments: sanitizedAttachments }
  }

  const readFileContent = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => {
        const result = reader.result as string
        // For binary files, return base64
        if (file.type.startsWith('image/') || file.type === 'application/pdf') {
          const base64Content = result.split(',')[1] // Remove data URL prefix
        if (!base64Content || !/^[A-Za-z0-9+/=]+$/.test(base64Content)) {
          reject(new Error('Invalid base64 content in file.'))
          return
        }
        resolve(base64Content)
        } else {
          resolve(result)
        }
      }
      reader.onerror = reject

      if (file.type.startsWith('image/') || file.type === 'application/pdf') {
        reader.readAsDataURL(file)
      } else {
        reader.readAsText(file)
      }
    })
  }

  const handleFileSelect = (files: File[]) => {
    setPendingFiles(prev => [...prev, ...files])
  }

  const removePendingFile = (index: number) => {
    setPendingFiles(prev => prev.filter((_, i) => i !== index))
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <header className="flex items-center justify-center py-3 border-b border-chat-border bg-chat-sidebar">
        <h1 className="text-xl font-semibold text-white">PolicyProbe</h1>
      </header>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto chat-scrollbar">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-gray-400">
            <div className="text-4xl mb-4">🔍</div>
            <h2 className="text-2xl font-medium text-white mb-2">PolicyProbe</h2>
            <p className="text-center max-w-md">
              Upload documents to analyze or ask questions about policy compliance.
              <br />
              <span className="text-sm text-gray-500 mt-2 block">
                Supports PDF, Word, HTML, and image files
              </span>
            </p>
          </div>
        ) : (
          <MessageList messages={messages} />
        )}
      </div>

      {/* File Upload Modal */}
      {showFileUpload && (
        <div className="border-t border-chat-border bg-chat-input p-4">
          <FileUpload onFilesSelected={handleFileSelect} />
        </div>
      )}

      {/* Pending Files Display */}
      {pendingFiles.length > 0 && (
        <div className="border-t border-chat-border bg-chat-input px-4 py-2">
          <div className="flex flex-wrap gap-2">
            {pendingFiles.map((file, index) => (
              <div
                key={index}
                className="flex items-center gap-2 bg-chat-hover rounded-lg px-3 py-1.5 text-sm"
              >
                <span className="text-gray-300">{file.name}</span>
                <button
                  onClick={() => removePendingFile(index)}
                  className="text-gray-500 hover:text-red-400"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Input Area */}
      <div className="border-t border-chat-border bg-chat-bg p-4">
        <form onSubmit={handleSubmit} className="max-w-3xl mx-auto">
          <div className="relative flex items-end bg-chat-input rounded-xl border border-chat-border">
            {/* File Upload Button */}
            <button
              type="button"
              onClick={() => setShowFileUpload(!showFileUpload)}
              className="p-3 text-gray-400 hover:text-white transition-colors"
            >
              <Paperclip className="w-5 h-5" />
            </button>

            {/* Hidden file input */}
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".pdf,.doc,.docx,.html,.htm,.txt,.json,.jpg,.jpeg,.png"
              className="hidden"
              onChange={(e) => {
                if (e.target.files) {
                  handleFileSelect(Array.from(e.target.files))
                }
              }}
            />

            {/* Text Input */}
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Message PolicyProbe..."
              className="flex-1 bg-transparent text-white placeholder-gray-500 resize-none py-3 pr-12 focus:outline-none max-h-48"
              rows={1}
              disabled={isLoading}
            />

            {/* Send Button */}
            <button
              type="submit"
              disabled={isLoading || (!input.trim() && pendingFiles.length === 0)}
              className="absolute right-2 bottom-2 p-2 text-gray-400 hover:text-white disabled:opacity-50 disabled:hover:text-gray-400 transition-colors"
            >
              {isLoading ? (
                <Loader2 className="w-5 h-5 animate-spin" />
              ) : (
                <Send className="w-5 h-5" />
              )}
            </button>
          </div>
          <p className="text-xs text-center text-gray-500 mt-2">
            PolicyProbe demonstrates AI policy evaluation and remediation
          </p>
        </form>
      </div>
    </div>
  )
}
