import { readFile } from 'node:fs/promises'
import { NextResponse } from 'next/server'

const STATE_PATH = '/tmp/next-16.2.4-image-local-rewrite-state.json'

async function readState() {
  try {
    const raw = await readFile(STATE_PATH, 'utf8')
    return JSON.parse(raw)
  } catch {
    return { backendRequests: [] }
  }
}

export async function GET() {
  return NextResponse.json(await readState())
}
