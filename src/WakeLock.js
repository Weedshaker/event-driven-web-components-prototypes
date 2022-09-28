// @ts-check

/* global navigator */

import { Shadow } from './Shadow.js'

/**
 * Wake Lock
 *
 * @export
 * @function WakeLock
 * @param {Function | *} ChosenClass
 * @property {
    wakeLock,
    requestWakeLock,
    releaseListener
  }
 * @return {CustomElementConstructor | *}
 */
export const WakeLock = (ChosenClass = Shadow()) => class WakeLock extends ChosenClass {
  constructor (...args) {
    super(...args)

    this.wakeLock = null

    this.releaseListener = event => console.log('WakeLock released!')
    this.visibilitychangeListener = event => {
      if (this.wakeLock !== null && document.visibilityState === 'visible') this.requestWakeLock()
    }
  }

  connectedCallback () {
    document.addEventListener('visibilitychange', this.visibilitychangeListener)
  }

  disconnectedCallback () {
    document.removeEventListener('visibilitychange', this.visibilitychangeListener)
  }

  /**
   * @return {Promise<WakeLock>}
   */
  requestWakeLock () {
    try {
      // @ts-ignore
      const wakeLockPromise = navigator.wakeLock.request('screen')
      wakeLockPromise.then(wakeLock => {
        this.wakeLock = wakeLock
        this.wakeLock.addEventListener('release', this.releaseListener, { once: true })
      })
      return wakeLockPromise
    } catch (error) {
      return Promise.reject(new Error(`${error.name}, ${error.message}`))
    }
  }

  releaseWakeLock () {
    if (!this.wakeLock) return
    this.wakeLock.release()
    this.wakeLock = null
  }
}
