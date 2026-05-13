import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth/next'
import { createHash } from 'crypto'
import { appendFile } from 'fs/promises'
import { join } from 'path'

const AUDIT_LOG_PATH = join(process.cwd(), 'logs', 'ai_audit.ndjson')

async function writeAuditLog(entry: Record<string, unknown>): Promise<void> {
  const line = JSON.stringify(entry) + '\n'
  try {
    await appendFile(AUDIT_LOG_PATH, line, { encoding: 'utf8', flag: 'a' })
  } catch (logError) {
    // Log to stderr so the audit failure is visible but never silently swallowed
    console.error('[AUDIT] Failed to write audit log entry:', logError, entry)
  }
}

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'
const API_SECRET_KEY = process.env.API_SECRET_KEY
const BACKEND_API_KEY = process.env.BACKEND_API_KEY

if (!BACKEND_API_KEY) {
  throw new Error('BACKEND_API_KEY environment variable is not set. Inter-agent communication requires authentication.')
}

export async function POST(request: NextRequest) {
  const requestTimestamp = new Date().toISOString()
  // Extract principal from standard headers (Bearer token sub, API key, or anonymous)
  const authHeader = request.headers.get('authorization') || ''
  const principalHeader = request.headers.get('x-user-id') || ''
  const principal = principalHeader || (authHeader ? `bearer:${createHash('sha256').update(authHeader).digest('hex').slice(0, 16)}` : 'anonymous')

  let body: Record<string, unknown>
  try {
    body = await request.json()

    // --- Input validation ---
    if (!body || typeof body !== 'object') {
      return NextResponse.json(
        { detail: 'Invalid request body: must be a JSON object.' },
        { status: 400 }
      )
    }

    if (typeof body.message !== 'string' || body.message.trim().length === 0) {
      return NextResponse.json(
        { detail: 'Invalid input: "message" must be a non-empty string.' },
        { status: 400 }
      )
    }

    const MAX_MESSAGE_LENGTH = 4000
    if (body.message.length > MAX_MESSAGE_LENGTH) {
      return NextResponse.json(
        { detail: `Invalid input: "message" must not exceed ${MAX_MESSAGE_LENGTH} characters.` },
        { status: 400 }
      )
    }

    // --- Input sanitization ---
    // Remove ASCII control characters (except tab, newline, carriage return)
    const sanitizedMessage = body.message
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
      .trim()

    // Build a sanitized payload with only the expected fields
    const sanitizedBody: Record<string, unknown> = {
      message: sanitizedMessage,
    }

    // Optionally forward a conversation_id if present and valid
    if (body.conversation_id !== undefined) {
      if (typeof body.conversation_id !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(body.conversation_id)) {
        return NextResponse.json(
          { detail: 'Invalid input: "conversation_id" must be an alphanumeric string up to 128 characters.' },
          { status: 400 }
        )
      }
      sanitizedBody.conversation_id = body.conversation_id
    }

        const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${BACKEND_API_KEY}`,
      },
      body: JSON.stringify(body),
    })

    const data = await response.json()
    const responseTimestamp = new Date().toISOString()

    // Extract model identifier from response if present, fall back to request body field
    const modelId =
      (data as Record<string, unknown>)?.model ||
      (body as Record<string, unknown>)?.model ||
      'unknown'

    if (!response.ok) {
      await writeAuditLog({
        event: 'ai_chat_backend_error',
        timestamp: requestTimestamp,
        response_timestamp: responseTimestamp,
        principal,
        model: modelId,
        input_hash: inputHash,
        http_status: response.status,
        output_summary: JSON.stringify(data).slice(0, 512),
      })
      return NextResponse.json(data, { status: response.status })
    }

    // Audit log: successful AI interaction
    await writeAuditLog({
      event: 'ai_chat_response',
      timestamp: requestTimestamp,
      response_timestamp: responseTimestamp,
      principal,
      model: modelId,
      input_hash: inputHash,
      // Store a hash of the output for integrity verification without full PII retention
      output_hash: createHash('sha256').update(JSON.stringify(data)).digest('hex'),
      // Store a truncated output excerpt for forensic readiness
      output_excerpt: JSON.stringify(data).slice(0, 512),
    })

    return NextResponse.json(data)
  } catch (error) {
    const errorTimestamp = new Date().toISOString()
    console.error('Backend proxy error:', error)
    await writeAuditLog({
      event: 'ai_chat_proxy_failure',
      timestamp: requestTimestamp,
      error_timestamp: errorTimestamp,
      principal,
      input_hash: inputHash,
      error: String(error),
    })
    return NextResponse.json(
      {
        detail: 'Failed to connect to backend service',
        policy_error: {
          type: 'general',
          message: 'Backend service unavailable',
        },
      },
      { status: 503 }
    )
  }
}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(sanitizedBody),
    })

    const data = await response.json()

    if (!response.ok) {
      // Minimise error responses — only forward safe, user-facing fields
      const errorPayload: Record<string, unknown> = {}
      if (data?.detail !== undefined) errorPayload.detail = data.detail
      if (data?.policy_error !== undefined) errorPayload.policy_error = data.policy_error
      return NextResponse.json(errorPayload, { status: response.status })
    }

    // Minimise success responses — only forward known, user-facing fields
    const allowedPayload: Record<string, unknown> = {}
    if (data?.response !== undefined) allowedPayload.response = data.response
    if (data?.session_id !== undefined) allowedPayload.session_id = data.session_id
    if (data?.policy_error !== undefined) allowedPayload.policy_error = data.policy_error

    return NextResponse.json(allowedPayload)
  } catch (error) {
    console.error('Backend proxy error:', error)
    return NextResponse.json(
      {
        detail: 'Failed to connect to backend service',
        policy_error: {
          type: 'general',
          message: 'Backend service unavailable',
        },
      },
      { status: 503 }
    )
  }
}
