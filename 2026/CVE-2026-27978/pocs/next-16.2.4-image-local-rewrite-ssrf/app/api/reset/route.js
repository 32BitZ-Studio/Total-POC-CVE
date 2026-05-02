import { writeFile } from 'node:fs/promises'
import { NextResponse } from 'next/server'

const STATE_PATH = '/tmp/next-16.2.4-image-local-rewrite-state.json'

export async function POST() {
  await writeFile(STATE_PATH, JSON.stringify({ backendRequests: [] }, null, 2))
  return NextResponse.json({ ok: true })
}
