'use client'

import { useState, useCallback, useRef } from 'react'
import { Upload, FileText, Image, File } from 'lucide-react'

interface FileUploadProps {
  onFilesSelected: (files: File[]) => void
}

// Patterns that indicate prompt injection, hidden instructions, or encoded payloads
const MALICIOUS_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
  /system\s*:\s*(you\s+are|act\s+as|pretend)/i,
  /\[\s*(system|assistant|user)\s*\]/i,
  /<\s*\|\s*(system|endoftext|im_start|im_end)\s*\|\s*>/i,
  /\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}/,  // excessive unicode escapes
  /(?:[A-Za-z0-9+/]{40,}={0,2})(?:\s+[A-Za-z0-9+/]{40,}={0,2}){2,}/, // large base64 blobs
  /\x00/,  // null bytes
  /jailbreak/i,
  /prompt\s*injection/i,
  /disregard\s+(your|all|any)\s+(previous|prior|safety|ethical)/i,
]

const TEXT_BASED_TYPES = new Set([
  'text/html',
  'text/plain',
  'application/json',
])

async function scanFileContent(file: File): Promise<boolean> {
  // Only scan text-based files for malicious content
  if (!TEXT_BASED_TYPES.has(file.type) && !file.name.match(/\.(txt|html?|json)$/i)) {
    return true // non-text files pass content scan (type/extension already validated)
  }

  // Enforce a reasonable size limit (5 MB) to prevent DoS via huge files
  const MAX_SIZE = 5 * 1024 * 1024
  if (file.size > MAX_SIZE) {
    console.warn(`File "${file.name}" exceeds maximum allowed size of 5 MB.`)
    return false
  }

  try {
    const text = await file.text()

    for (const pattern of MALICIOUS_PATTERNS) {
      if (pattern.test(text)) {
        console.warn(`File "${file.name}" failed content scan: matched pattern ${pattern}`)
        return false
      }
    }
    return true
  } catch {
    console.warn(`File "${file.name}" could not be read for content scanning.`)
    return false
  }
}

async function sanitizeFiles(files: File[]): Promise<File[]> {
  const results = await Promise.all(
    files.map(async (file) => ({ file, safe: await scanFileContent(file) }))
  )
  return results.filter((r) => r.safe).map((r) => r.file)
}

// ---------------------------------------------------------------------------
// PII patterns to detect and redact from text content
// ---------------------------------------------------------------------------
const PII_PATTERNS: { name: string; pattern: RegExp; replacement: string }[] = [
  {
    name: 'SSN',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    replacement: '[REDACTED-SSN]',
  },
  {
    name: 'CreditCard',
    pattern: /\b(?:\d[ -]?){13,16}\b/g,
    replacement: '[REDACTED-CC]',
  },
  {
    name: 'Email',
    pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    replacement: '[REDACTED-EMAIL]',
  },
  {
    name: 'Phone',
    pattern: /\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
    replacement: '[REDACTED-PHONE]',
  },
]

/** Returns true when the MIME type / extension indicates readable text. */
function isTextFile(file: File): boolean {
  const textTypes = ['text/plain', 'text/html', 'application/json']
  const textExtensions = ['.txt', '.html', '.htm', '.json']
  return (
    textTypes.includes(file.type) ||
    textExtensions.some((ext) => file.name.toLowerCase().endsWith(ext))
  )
}

/**
 * Reads a text file, redacts PII patterns, and returns a new File whose
 * content has been sanitised.  Non-text files are returned unchanged but
 * renamed to signal they were not scanned.
 */
async function redactPIIFromFile(file: File): Promise<File> {
  if (!isTextFile(file)) {
    // Binary files (PDF, images, DOCX) cannot be trivially scanned here;
    // return as-is but preserve the original so the caller is aware.
    return file
  }

  const originalText = await file.text()
  let redactedText = originalText

  for (const { pattern, replacement } of PII_PATTERNS) {
    redactedText = redactedText.replace(pattern, replacement)
  }

  // Only create a new File object when the content actually changed.
  if (redactedText === originalText) {
    return file
  }

  return new File([redactedText], file.name, {
    type: file.type,
    lastModified: file.lastModified,
  })
}

/** Runs PII redaction over every file in the array concurrently. */
async function redactPIIFromFiles(files: File[]): Promise<File[]> {
  return Promise.all(files.map(redactPIIFromFile))
}
// ---------------------------------------------------------------------------

export function FileUpload({ onFilesSelected }: FileUploadProps) {
  const [isDragOver, setIsDragOver] = useState(false)

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault()
      setIsDragOver(false)

            const files = Array.from(e.dataTransfer.files)
      const validFiles = files.filter(isValidFileType)

      if (validFiles.length > 0) {
        redactPIIFromFiles(validFiles).then((sanitisedFiles) => {
          onFilesSelected(sanitisedFiles)
        })
      }
        })
      }
    },
    [onFilesSelected]
  )

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragOver(false)
  }, [])

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      if (e.target.files) {
                const files = Array.from(e.target.files)
        const validFiles = files.filter(isValidFileType)

        if (validFiles.length > 0) {
          redactPIIFromFiles(validFiles).then((sanitisedFiles) => {
            onFilesSelected(sanitisedFiles)
          })
        }
          })
        }
      }
    },
    [onFilesSelected]
  )

  return (
    <div
      className={`file-upload-zone rounded-lg p-6 text-center cursor-pointer ${
        isDragOver ? 'drag-over' : ''
      }`}
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
    >
      <input
        type="file"
        multiple
        accept=".pdf,.doc,.docx,.html,.htm,.txt,.json,.jpg,.jpeg,.png"
        className="hidden"
        id="file-upload-input"
        onChange={handleFileInput}
      />
      <label htmlFor="file-upload-input" className="cursor-pointer">
        <Upload className="w-10 h-10 text-gray-400 mx-auto mb-3" />
        <p className="text-gray-300 mb-2">
          Drag and drop files here, or click to browse
        </p>
        <div className="flex justify-center gap-4 text-xs text-gray-500">
          <div className="flex items-center gap-1">
            <FileText className="w-4 h-4" />
            <span>PDF, DOC, HTML</span>
          </div>
          <div className="flex items-center gap-1">
            <Image className="w-4 h-4" />
            <span>JPG, PNG</span>
          </div>
          <div className="flex items-center gap-1">
            <File className="w-4 h-4" />
            <span>TXT, JSON</span>
          </div>
        </div>
      </label>
    </div>
  )
}

function isValidFileType(file: File): boolean {
  const validTypes = [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/html',
    'text/plain',
    'application/json',
    'image/jpeg',
    'image/png',
  ]

  const validExtensions = ['.pdf', '.doc', '.docx', '.html', '.htm', '.txt', '.json', '.jpg', '.jpeg', '.png']

  const hasValidType = validTypes.includes(file.type)
  const hasValidExtension = validExtensions.some(ext =>
    file.name.toLowerCase().endsWith(ext)
  )

  return hasValidType || hasValidExtension
}
