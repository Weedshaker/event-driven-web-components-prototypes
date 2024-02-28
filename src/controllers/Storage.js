// @ts-check

/* global HTMLElement */
/* global localStorage */

/** @typedef { WindowLocalStorage | WindowSessionStorage } STORAGE_TYPE_INTERFACE */
const STORAGE_TYPE = {
  localStorage: localStorage,
  sessionStorage: sessionStorage,
  get default () {
    return this.localStorage
  }
}

/**
 * As a controller, this component becomes a storage manager and organizes events
 * TODO: in progress!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *
 * @export
 * @class Storage
 */
export default class Storage extends HTMLElement {
  constructor () {
    super()

    /** @type {string | null} */
    let lastTimes = null

    /**
     * Listens to the event name/typeArg: 'set'
     *
     * @param {CustomEvent & {detail: { key: string, value: any, storageType?: 'localStorage' }}} event
     * @return {void}
     */
    this.setListener = event => {
      if (event.detail.key === undefined) return this.respond(event.detail.resolve, undefined, {key: null, value: null, message: 'Key is missing!', error: true})
      if (event.detail.value === undefined) return this.respond(event.detail.resolve, undefined, {key: event.detail.key, value: this.getListener(event.detail.key), message: 'Value is missing!', error: true})
      try {
        let newData
        this.getStorage(event.detail.storageType).setItem(event.detail.key, JSON.stringify(newData = Object.assign(this.getListener(event.detail.key), event.detail.value)))
        this.respond(event.detail.resolve, 'storage-data', {key: event.detail.key, value: newData, message: 'Success!', error: false})
      } catch (error) {
        this.respond(event.detail.resolve, undefined, {key: event.detail.key, value: this.getListener(event.detail.key), message: `Most likely error at JSON.stringify: ${error}`, error: true})
      } 
    }

    /**
     * Listens to the event name/typeArg: 'get'
     *
     * @param {CustomEvent & {detail: {key: string, storageType?: 'localStorage'}} | string | any} event
     * @return {any}
     */
    this.getListener = event => {
      let value = null
      const key = typeof event === 'string'
        ? event
        : event.detail.key
      if (!key.trim()) return this.respond(event.detail?.resolve, undefined, {key: null, value: null, message: 'Key is missing!', error: true}) || value
      try {
        const found = this.getStorage(event.detail.storageType).hasOwnProperty(key)
        this.respond(event.detail?.resolve, 'storage-data', {
          key,
          value: (value = JSON.parse(this.getStorage(event.detail.storageType).getItem(key) || '{}')),
          message: found
            ? 'Success!'
            : 'Item not found!',
          error: found
            ? false
            : true
        })
      } catch (error) {
        this.respond(event.detail?.resolve, undefined, {key, value: null, message: `Most likely error at JSON.parse: ${error}`, error: true})
      }
      return value
    }

    /**
     * Listens to the event name/typeArg: 'remove'
     *
     * @param {CustomEvent & {detail: RemoveTimeDetail}} event
     * @return {void}
     */
    this.removeListener = event => {
      if (event && event.detail && event.detail.date && event.detail.time) {
        let times = this.getListener()
        const key = event.detail.date
        if (key in times) {
          lastTimes = JSON.stringify(times)
          times[key].splice(times[key].indexOf(event.detail.time), 1)
          if (!times[key].length) delete times[key]
          this.getStorage(event.detail.storageType).setItem('times', JSON.stringify(times))
        }
        if (typeof event.detail.resolve == 'function') event.detail.resolve(times)
      }
    }

    /**
     * Listens to the event name/typeArg: 'undo'
     *
     * @param {CustomEvent & {detail: UndoTimeDetail}} event
     * @return {void}
     */
    this.undoListener = event => {
      if (lastTimes) {
        this.getStorage(event.detail.storageType).setItem('times', lastTimes)
        if (event && event.detail && typeof event.detail.resolve == 'function') event.detail.resolve(JSON.parse(lastTimes))
        lastTimes = null
      }
    }
  }

  connectedCallback () {
    this.addEventListener(this.getAttribute('storage-set') || 'storage-set', this.setListener)
    this.addEventListener(this.getAttribute('storage-get') || 'storage-get', this.getListener)
    this.addEventListener(this.getAttribute('storage-remove') || 'storage-remove', this.removeListener)
    this.addEventListener(this.getAttribute('storage-undo') || 'storage-undo', this.undoListener)
  }

  disconnectedCallback () {
    this.removeEventListener(this.getAttribute('storage-set') || 'storage-set', this.setListener)
    this.removeEventListener(this.getAttribute('storage-get') || 'storage-get', this.getListener)
    this.removeEventListener(this.getAttribute('storage-remove') || 'storage-remove', this.removeListener)
    this.removeEventListener(this.getAttribute('storage-undo') || 'storage-undo', this.undoListener)
  }

  respond (resolve, name, detail) {
    if (typeof resolve === 'function') return resolve(detail)
    if (typeof name === 'string') this.dispatchEvent(new CustomEvent(name, {
      detail,
      bubbles: true,
      cancelable: true,
      composed: true
    }))
  }

  /** @return {STORAGE_TYPE_INTERFACE} */
  getStorage (type) {
    return STORAGE_TYPE[type] || STORAGE_TYPE[this.getAttribute('storage-type')] || STORAGE_TYPE.default
  }
}
