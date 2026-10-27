// dsh-ssh-safe — bounded connection shutdown.
//
// ssh2's end() asks the peer to close and waits for the socket to go away. A
// peer that never answers leaves that promise pending forever, which is why
// every close path needs a deadline.
//
// The earlier implementation armed the deadline with
//   setTimeout(finish, 1500).unref?.()
// which is wrong twice over: unref() lets Node exit while the wait is still
// pending (so the promise never settles when nothing else keeps the loop
// alive), and there was no fallback if 'close' never arrived.

/**
 * Close one ssh2 client, returning after at most `timeoutMs`.
 * Never rejects: shutdown failures are not actionable for the caller.
 *
 * @param {object} client an ssh2 Client (or any object with end/once)
 * @param {number} [timeoutMs]
 * @returns {Promise<boolean>} true when the peer confirmed the close
 */
export function closeClient(client, timeoutMs = 1500) {
  if (!client) return Promise.resolve(false)
  return new Promise((resolve) => {
    let settled = false
    let confirmed = false

    const finish = (viaPeer) => {
      if (settled) return
      settled = true
      confirmed = viaPeer === true
      // The timer is NOT unref'd: it is the only thing that can settle this
      // promise if the peer is silent, so it must keep the loop alive.
      clearTimeout(timer)
      resolve(confirmed)
    }

    const timer = setTimeout(() => finish(false), timeoutMs)

    try {
      if (typeof client.once === 'function') client.once('close', () => finish(true))
    } catch { /* a broken client must not throw out of shutdown */ }

    try {
      if (typeof client.end === 'function') client.end()
      else finish(false)
    } catch {
      finish(false)
    }
  })
}
