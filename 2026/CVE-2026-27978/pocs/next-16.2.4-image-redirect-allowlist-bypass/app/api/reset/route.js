import { writeFile } from 'node:fs/promises'
import { NextResponse } from 'next/server'

const STATE_PATH = '/tmp/next-16.2.4-image-redirect-state.json'

export async function POST() {
  await writeFile(
    STATE_PATH,
    JSON.stringify({ allowedRequests: [], disallowedRequests: [] }, null, 2)
  )
  return NextResponse.json({ ok: true })
}
