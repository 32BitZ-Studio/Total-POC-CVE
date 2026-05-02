import { readFile } from 'node:fs/promises'

const STATE_PATH = '/tmp/next-16.2.4-image-redirect-state.json'

async function readState() {
  try {
    const raw = await readFile(STATE_PATH, 'utf8')
    return JSON.parse(raw)
  } catch {
    return { allowedRequests: [], disallowedRequests: [] }
  }
}

export const dynamic = 'force-dynamic'

export default async function HomePage() {
  const state = await readState()

  return (
    <main>
      <h1>Next.js 16.2.4 Image Redirect Allowlist Bypass</h1>
      <p>
        The image optimizer is configured to allow only the upstream on port
        4100, but that upstream redirects to a second upstream on port 4200.
      </p>
      <h2>Observed Upstream Requests</h2>
      <pre>{JSON.stringify(state, null, 2)}</pre>
    </main>
  )
}
