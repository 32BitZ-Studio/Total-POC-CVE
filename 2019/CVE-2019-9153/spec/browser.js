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
const log = (function (Terminal) {
  if (!Terminal) {
    console.info(
      '(tape-xterm) Terminal not found: ignoring tape decoration calls'
    )
    return
  }
  Terminal.applyAddon(require('xterm/lib/addons/fit/fit'))
  const term = new Terminal({
    convertEol: true,
    disableStdin: true,
    fontSize: 12
  })
  term.open(document.querySelector('#terminal'))
  term.fit()
  return txt => term.write(txt)
})(typeof Terminal === 'function' && Terminal)

const streams = []

module.exports = function (tape) {
  if (!log || streams.findIndex(spec => spec.tape === tape) >= 0) return tape
  const stream = tape.createStream()
  stream.on('data', log)
  streams.push({ stream, tape })
  return tape
}

module.exports.log = log
