// @ts-check

/* global HTMLElement */
/* global localStorage */

/** @typedef { WindowLocalStorage | WindowSessionStorage | any } STORAGE */
/** @typedef { STORAGE } STORAGE_TYPE_INTERFACE */
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

    this.oldStorage = new Map()

    /**
     * Listens to the event name/typeArg: 'set'
     *
     * @param {CustomEvent & {detail: { key: string, value: any, storageType?: 'localStorage' }} | string | any} event
     * @param {any} [value=undefined]
     * @param {Storage} [storage=undefined]
     * @return {boolean}
     */
    this.setListener = (event, value, storage) => {
      const key = typeof event === 'string'
        ? event
        : event.detail.key
      if (!key.trim()) return this.respond(event.detail?.resolve, undefined, {key: null, value: null, message: 'Key is missing!', error: true}) || false
      if (!value && event.detail?.value) value = event.detail.value
      if (value === undefined) return this.respond(event.detail?.resolve, undefined, {key, value: this.getListener(key, event.detail?.storageType || storage), message: 'Value is missing!', error: true}) || false
      try {
        const oldValue = this.getListener(key, event.detail?.storageType || storage)
        this.oldStorage.set(key, oldValue)
        let newValue
        this.getStorage(event.detail?.storageType || storage).setItem(key, JSON.stringify(newValue = Object.assign(oldValue, value)))
        this.respond(event.detail?.resolve, 'storage-data', {key, value: newValue, message: 'Success!', error: false})
      } catch (error) {
        return this.respond(event.detail?.resolve, undefined, {key, value: this.getListener(key, event.detail?.storageType || storage), message: `Error at setItem, most likely error at JSON.stringify: ${error}`, error: true}) || false
      }
      return true
    }

    /**
     * Listens to the event name/typeArg: 'get'
     *
     * @param {CustomEvent & {detail: {key: string, storageType?: 'localStorage'}} | string | any} event
     * @param {Storage} [storage=undefined]
     * @return {any}
     */
    this.getListener = (event, storage) => {
      let value = null
      const key = typeof event === 'string'
        ? event
        : event.detail.key
      if (!key.trim()) return this.respond(event.detail?.resolve, undefined, {key: null, value: null, message: 'Key is missing!', error: true}) || value
      try {
        const found = this.getStorage(event.detail?.storageType || storage).hasOwnProperty(key)
        this.respond(event.detail?.resolve, 'storage-data', {
          key,
          value: (value = JSON.parse(this.getStorage(event.detail?.storageType || storage).getItem(key) || '{}')),
          message: found
            ? 'Success!'
            : 'Item not found!',
          error: found
            ? false
            : true
        })
      } catch (error) {
        this.respond(event.detail?.resolve, undefined, {key, value: null, message: `Error at getItem, most likely error at JSON.parse: ${error}`, error: true})
      }
      return value
    }

    /**
     * Listens to the event name/typeArg: 'remove'
     *
     * @param {CustomEvent & {detail: {key: string, storageType?: 'localStorage'}} | string | any} event
     * @param {Storage} [storage=undefined]
     * @return {void}
     */
    this.removeListener = (event, storage) => {
      const key = typeof event === 'string'
        ? event
        : event.detail.key
      if (!key.trim()) return this.respond(event.detail?.resolve, undefined, {key: null, value: null, message: 'Key is missing!', error: true})
      try {
        const oldValue = this.getListener(key, event.detail?.storageType || storage)
        this.oldStorage.set(key, oldValue)
        this.getStorage(event.detail?.storageType || storage).removeItem(key)
        this.respond(event.detail?.resolve, 'storage-data-removed', {
          key,
          value: oldValue,
          message: 'Success!',
          error: false
        })
      } catch (error) {
        this.respond(event.detail?.resolve, undefined, {key: key, value: null, message: `Error at removeItem: ${error}`, error: true})
      }
    }

    /**
     * Listens to the event name/typeArg: 'undo'
     *
     * @param {CustomEvent & {detail: {key: string, storageType?: 'localStorage'}} | any} event
     * @return {void}
     */
    this.undoListener = event => {
      if (!event.detail.key.trim()) return this.respond(event.detail.resolve, undefined, {key: null, value: null, message: 'Key is missing!', error: true})
      const oldValue = this.oldStorage.get(event.detail.key)
      if (oldValue) {
        try {
          let success
          this.removeListener(event.detail.key, event.detail.storage)
          this.respond(event.detail.resolve, 'storage-data-undone', {
            key: event.detail.key,
            value: (success = this.setListener(event.detail.key, oldValue, event.detail.storage))
              ? oldValue
              : this.getListener(event.detail.key, event.detail.storageType),
            message: success
              ? 'Success!'
              : 'Not undone!',
            error: success
              ? false
              : true
          })
          this.oldStorage.delete(event.detail.key)
        } catch (error) {
          this.respond(event.detail.resolve, undefined, {key: event.detail.key, value: this.getListener(event.detail.key, event.detail.storageType), message: `Error at undo: ${error}`, error: true})
        }
      } else {
        this.respond(event.detail.resolve, undefined, {key: event.detail.key, value: this.getListener(event.detail.key, event.detail.storageType), message: 'No old value to undo!', error: true})
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

  /**
   *
   *
   * @param {(any)=>void} resolve
   * @param {string|undefined} name
   * @param {any} detail
   * @return {void | any}
   */
  respond (resolve, name, detail) {
    if (typeof resolve === 'function') return resolve(detail)
    if (typeof name === 'string') this.dispatchEvent(new CustomEvent(name, {
      detail,
      bubbles: true,
      cancelable: true,
      composed: true
    }))
  }

  /**
   * @param {'localStorage' | 'sessionStorage'} [type='localStorage']
   * @return {STORAGE}
   */
  getStorage (type) {
    return STORAGE_TYPE[type] || STORAGE_TYPE[this.getAttribute('storage-type')] || STORAGE_TYPE.default
  }
}
