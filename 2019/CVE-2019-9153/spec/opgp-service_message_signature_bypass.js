const log = require('./browser').log || console.log.bind(console)
const OTHERPUBKEY = require('./create_tampered_message').OTHERPUBKEY

const opgp = require('opgp-service').default({
  use_native: !!(self.crypto && self.crypto.subtle)
})

// opgp sign/verify API example
const text = 'Rob says wow !'
const passphrase = 'p@ssw0rd!'
const key = opgp.generateKey('john.doe@cve.io', {
  size: 1024,
  passphrase,
  unlocked: true
})

export function exampleSignVerify () {
  return opgp
    .sign(key, text)
    .then(
      signed => (
        log(`signed message is encrypted (AEAD_protect):\n${signed}\n`), signed
      )
    )
    .then(signed => opgp.verify(key, signed))
    .then(verified => log(`verified:\n${verified}\n\n`))
}

async function verifySignedMessage (message) {
  // should throw if message was not signed as in above example (i.e. AEAD-protected)
  return opgp.verify(opgp.getKeysFromArmor(OTHERPUBKEY), message)
}

export default verifySignedMessage
