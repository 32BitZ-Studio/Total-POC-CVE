/**
 * https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/Mailvelope_Extensions/Mailvelope_Extensions_pdf.html
 */
const openpgp = require('openpgp')
const OTHERPUBKEY = require('./create_tampered_message').OTHERPUBKEY

async function getOtherPubKey () {
  return (await openpgp.key.readArmored(OTHERPUBKEY)).keys[0]
}

async function verifySignedMessage (message) {
  return openpgp.default.verify({
    message: await openpgp.cleartext.readArmored(message),
    publicKeys: await getOtherPubKey(),
    streaming: false
  })
}

export default verifySignedMessage
