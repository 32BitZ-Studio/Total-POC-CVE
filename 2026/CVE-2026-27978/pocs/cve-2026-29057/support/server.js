const http = require('http')
const { readFileSync, writeFileSync } = require('fs')
const { spawn } = require('child_process')

const STATE_PATH = '/tmp/cve-2026-29057-state.json'
const BACKEND_PORT = 5000
const INTERMEDIARY_PORT = 4000

function readState() {
  try {
    return JSON.parse(readFileSync(STATE_PATH, 'utf8'))
  } catch {
    return { backendRequests: [] }
  }
}

function writeState(state) {
  writeFileSync(STATE_PATH, JSON.stringify(state, null, 2))
}

function resetState() {
  writeState({ backendRequests: [] })
}

function recordBackendRequest(method, url) {
  const state = readState()
  state.backendRequests.push(`${method} ${url}`)
  writeState(state)
}

resetState()

const backend = http.createServer((req, res) => {
  recordBackendRequest(req.method || 'UNKNOWN', req.url || '/')

  if (req.url && req.url.startsWith('/rewrites/')) {
    res.statusCode = 200
    res.end('rewrite-ok')
    return
  }

  if (req.url === '/secret') {
    res.statusCode = 200
    res.end('secret')
    return
  }

  res.statusCode = 404
  res.end('not-found')
})

const intermediary = http.createServer((req, res) => {
  const connectionHeader = Array.isArray(req.headers.connection)
    ? req.headers.connection.join(',')
    : req.headers.connection || ''
  const hopByHopHeaders = connectionHeader
    .split(',')
    .map((header) => header.trim().toLowerCase())
    .filter(Boolean)

  const forwardHeaders = {}
  for (const [key, value] of Object.entries(req.headers)) {
    if (key === 'connection') continue
    if (hopByHopHeaders.includes(key)) continue
    if (value !== undefined) {
      forwardHeaders[key] = value
    }
  }
  forwardHeaders.connection = 'keep-alive'

  const proxyReq = http.request(
    {
      hostname: '127.0.0.1',
      port: BACKEND_PORT,
      method: req.method,
      path: req.url,
      headers: forwardHeaders,
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 500, proxyRes.headers)
      proxyRes.pipe(res)
    }
  )

  proxyReq.on('error', () => {
    res.statusCode = 502
    res.end('Bad Gateway')
  })

  req.pipe(proxyReq)
})

const nextCli = require.resolve('next/dist/bin/next')
let nextProcess

function shutdown(code) {
  const finish = () => process.exit(code)
  if (nextProcess && !nextProcess.killed) {
    nextProcess.kill('SIGTERM')
  }
  intermediary.close(() => {
    backend.close(finish)
  })
}

backend.listen(BACKEND_PORT, '127.0.0.1', () => {
  intermediary.listen(INTERMEDIARY_PORT, '127.0.0.1', () => {
    nextProcess = spawn(
      process.execPath,
      [nextCli, 'start', '-H', '0.0.0.0', '-p', '3000'],
      {
        stdio: 'inherit',
      }
    )

    nextProcess.on('exit', (code) => {
      shutdown(code || 0)
    })
  })
})

process.on('SIGTERM', () => shutdown(0))
process.on('SIGINT', () => shutdown(0))
