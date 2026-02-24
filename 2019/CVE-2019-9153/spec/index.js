/**
 * @license MIT
 * @author Stephane M. Catala <stephane@zenyway.com>
 *
 * Copyright (C) 2019, Stephane M. Catala <stephane@zenyway.com>
 *
 * Permission is hereby granted, free of charge,
 * to any person obtaining a copy of this software
 * and associated documentation files (the "Software"),
 * to deal in the Software without restriction,
 * including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice
 * shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
require('regenerator-runtime/runtime')
const test = require('./browser')(require('tape'))
const createTamperedMessage = require('./create_tampered_message').default
const ORIGINAL = require('./create_tampered_message').ORIGINAL
const verifySignedMessage = require('./message_signature_bypass').default
const opgpServiceVerifySignedMessage = require('./opgp-service_message_signature_bypass')
  .default
const exampleSignVerify = require('./opgp-service_message_signature_bypass')
  .exampleSignVerify

test("CVE-2019-9153: a tampered message with a victim's standalone signature", t =>
  void createTamperedMessage()
    .then(tampered => verifySignedMessage(tampered))
    .then(function (result) {
      t.true(result.signatures[0].valid, 'verifies successfully')
      t.end()
    })
    .catch(function () {
      t.fail('should not raise an exception')
      t.end()
    }))

test("opgp-service: a tampered message with a victim's standalone signature", t =>
  void createTamperedMessage()
    .then(tampered =>
      rejectOnThrow(() => opgpServiceVerifySignedMessage(tampered))
    )
    .then(function () {
      t.fail('should raise an exception')
      t.end()
    })
    .catch(function (err) {
      t.equal(
        err && err.message,
        'Can only verify message with one literal data packet.',
        'raises an exception'
      )
      t.end()
    }))

test('opgp-service: a message signed without AEAD such that it can be tampered', t =>
  rejectOnThrow(() => opgpServiceVerifySignedMessage(ORIGINAL))
    .then(function () {
      t.fail('should raise an exception')
      t.end()
    })
    .catch(function (err) {
      t.equal(
        err && err.message,
        'Can only verify message with one literal data packet.',
        'raises an exception'
      )
      t.end()
    }))

test('example sign/verify with opgp-service', t => {
  exampleSignVerify()
    .then(() => t.end())
    .catch(() => {
      t.fail('should not throw')
      t.end()
    })
})

function rejectOnThrow (fn) {
  let result
  try {
    result = fn()
  } catch (err) {
    return Promise.reject(err)
  }
  return Promise.resolve(result)
}
