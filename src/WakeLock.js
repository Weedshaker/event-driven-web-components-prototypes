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

    this.releaseListener = event => {
      if (this.hasAttribute('info')) console.info('WakeLock released!')
    }
    this.activateListener = () => {
      if (this.hasAttribute('info')) console.info('WakeLock activated!')
    }
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
    if (this.wakeLock) return this.wakeLock
    try {
      // @ts-ignore
      const wakeLockPromise = navigator.wakeLock.request('screen')
      wakeLockPromise.then(wakeLock => {
        this.wakeLock = wakeLock
        this.wakeLock.addEventListener('release', this.releaseListener, { once: true })
        this.activateListener()
      })
      return wakeLockPromise
    } catch (error) {
      return Promise.reject(error)
    }
  }

  releaseWakeLock () {
    if (!this.wakeLock) return
    this.wakeLock.release()
    this.wakeLock = null
  }
}
