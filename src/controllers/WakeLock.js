// @ts-check

import { WakeLock as WakeLockPrototype } from '../WakeLock.js'

/**
 * Use the ../WakeLock.js as a controller
 * Example at: https://github.com/Weedshaker/InteractiveBreathing
 * As a controller, this component communicates exclusively through events
 *
 * @export
 * @class WakeLock
 * @type {CustomElementConstructor}
 */
export default class WakeLock extends WakeLockPrototype() {
  constructor (...args) {
    super({ mode: 'false' }, ...args)

    this.requestWakeLockListener = event => this.requestWakeLock()
    this.releaseWakeLockListener = event => this.releaseWakeLock()
  }

  connectedCallback () {
    this.addEventListener(this.getAttribute('request-wake-lock') || 'request-wake-lock', this.requestWakeLockListener)
    this.addEventListener(this.getAttribute('release-wake-lock') || 'release-wake-lock', this.releaseWakeLockListener)
  }

  disconnectedCallback () {
    this.removeEventListener(this.getAttribute('request-wake-lock') || 'request-wake-lock', this.requestWakeLockListener)
    this.removeEventListener(this.getAttribute('release-wake-lock') || 'release-wake-lock', this.releaseWakeLockListener)
  }
}