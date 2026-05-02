import { readFile } from 'node:fs/promises'

const STATE_PATH = '/tmp/next-16.2.4-image-local-rewrite-state.json'

async function readState() {
  try {
    const raw = await readFile(STATE_PATH, 'utf8')
    return JSON.parse(raw)
  } catch {
    return { backendRequests: [] }
  }
}

export const dynamic = 'force-dynamic'

export default async function HomePage() {
  const state = await readState()

  return (
    <main>
      <h1>Next.js 16.2.4 Image Local Rewrite SSRF</h1>
      <p>
        The image optimizer accepts a local URL under /allowed, then the app
        rewrite sends that request to a private upstream.
      </p>
      <h2>Observed Backend Requests</h2>
      <pre>{JSON.stringify(state, null, 2)}</pre>
    </main>
  )
}
