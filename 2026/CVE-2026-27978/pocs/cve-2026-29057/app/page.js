import { readFile } from 'node:fs/promises'

const STATE_PATH = '/tmp/cve-2026-29057-state.json'

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
      <h1>CVE-2026-29057</h1>
      <p>
        This app rewrites <code>/rewrites/*</code> to an external intermediary.
      </p>
      <p>
        The exploit sends a crafted chunked <code>DELETE</code> request and
        checks whether a smuggled <code>GET /secret</code> reaches the backend.
      </p>
      <h2>Observed Backend Requests</h2>
      <pre>{JSON.stringify(state, null, 2)}</pre>
    </main>
  )
}
