const http = require('http')
const { readFileSync, writeFileSync } = require('fs')
const { spawn } = require('child_process')

const STATE_PATH = '/tmp/next-16.2.4-image-redirect-state.json'
const ALLOWED_PORT = 4100
const DISALLOWED_PORT = 4200

const PNG_1X1 = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=',
  'base64'
)

function readState() {
  try {
    return JSON.parse(readFileSync(STATE_PATH, 'utf8'))
  } catch {
    return { allowedRequests: [], disallowedRequests: [] }
  }
}

function writeState(state) {
  writeFileSync(STATE_PATH, JSON.stringify(state, null, 2))
}

function resetState() {
  writeState({ allowedRequests: [], disallowedRequests: [] })
}

function record(kind, method, url) {
  const state = readState()
  state[kind].push(`${method} ${url}`)
  writeState(state)
}

resetState()

const allowed = http.createServer((req, res) => {
  record('allowedRequests', req.method || 'UNKNOWN', req.url || '/')
  const url = new URL(req.url || '/', `http://127.0.0.1:${ALLOWED_PORT}`)

  if (url.pathname === '/allowed/redirect.png') {
    res.statusCode = 302
    const redirect = new URL(
      `http://127.0.0.1:${DISALLOWED_PORT}/blocked/private.png`
    )
    redirect.search = url.search
    res.setHeader(
      'Location',
      redirect.href
    )
    res.end('redirecting')
    return
  }

  res.statusCode = 404
  res.end('not-found')
})

const disallowed = http.createServer((req, res) => {
  record('disallowedRequests', req.method || 'UNKNOWN', req.url || '/')
  const url = new URL(req.url || '/', `http://127.0.0.1:${DISALLOWED_PORT}`)

  if (url.pathname === '/blocked/private.png') {
    res.statusCode = 200
    res.setHeader('Content-Type', 'image/png')
    res.setHeader('Cache-Control', 'public, max-age=60')
    res.end(PNG_1X1)
    return
  }

  res.statusCode = 404
  res.end('not-found')
})

const nextCli = require.resolve('next/dist/bin/next')
let nextProcess

function shutdown(code) {
  const finish = () => process.exit(code)
  if (nextProcess && !nextProcess.killed) {
    nextProcess.kill('SIGTERM')
  }
  allowed.close(() => {
    disallowed.close(finish)
  })
}

allowed.listen(ALLOWED_PORT, '127.0.0.1', () => {
  disallowed.listen(DISALLOWED_PORT, '127.0.0.1', () => {
    nextProcess = spawn(
      process.execPath,
      [nextCli, 'start', '-H', '0.0.0.0', '-p', '3000'],
      { stdio: 'inherit' }
    )

    nextProcess.on('exit', (code) => {
      shutdown(code || 0)
    })
  })
})

process.on('SIGTERM', () => shutdown(0))
process.on('SIGINT', () => shutdown(0))
