// @ts-check

import { WebWorker } from '../WebWorker.js'

/** @typedef {{ privateKeyEpoch: string, publicKeyEpoch: string }} DERIVED_KEY */
/** @typedef {{ epoch:string, derived?: DERIVED_KEY }} KEY_EPOCH */
/** @typedef {JsonWebKey | string} JSONWEBKEY_STRING */
/** @typedef {{ cryptoKey: CryptoKey, jsonWebKey?: JSONWEBKEY_STRING | string, epoch: string, derived?: DERIVED_KEY }} KEY */
/** @typedef {{ publicKey: KEY, privateKey: KEY }} KEY_PAIR */
/** @typedef {{ text: string, iv: Uint8Array<ArrayBuffer>, name: string, key: KEY_EPOCH }} ENCRYPTED */ // text: JSON.stringify({text: string, epoch: string})
/** @typedef {{ text: string, epoch: string, encrypted: { epoch: string, key: KEY_EPOCH }, key: KEY_EPOCH }} DECRYPTED */
/** @typedef {{ error: true, message: string, privateKey: KEY, publicKey: KEY }} DERIVE_ERROR */
/** @typedef {{ error: true, message: string, text: string, key: KEY }} ENCRYPTED_ERROR */
/** @typedef {{ error: true, message: string, encrypted: ENCRYPTED, key: KEY }} DECRYPTED_ERROR */
/** @typedef {{ error: true, message: string, jsonWebKey: JsonWebKey }} JSON_WEB_KEY_TO_CRYPTOKEY_ERROR */

/**
 * As a controller, this component becomes a crypto manager and organizes events
 * Inspired by: https://github.com/mdn/dom-examples/blob/main/web-crypto/derive-key/ecdh.js + https://getstream.io/blog/web-crypto-api-chat/
 * Caches are not async with promises as values, due to minor advantages but higher complexity
 *
 * @export
 * @class Crypto
 */
export default class Crypto extends WebWorker() {
  static #jsonWebCryptoKeysCache = {
    /**
     * caching the cryptoKeys by jsonWebKey as map-key
     *
     * @type {Map<string, CryptoKey>}
     */
    cryptoKeysCache: new Map(),
    /**
     * caching the jsonWebKey by cryptoKey as map-key
     *
     * @type {WeakMap<CryptoKey, JSONWEBKEY_STRING>}
     */
    jsonWebKeysCache: new WeakMap(),
    /**
     * getKeysCache
     * 
     * @returns {(key: CryptoKey | JSONWEBKEY_STRING) => CryptoKey | JSONWEBKEY_STRING | undefined}
     */
    get get() {
      return key => {
        if (key instanceof CryptoKey) {
          return this.jsonWebKeysCache.get(key)
        }
        return this.cryptoKeysCache.get(typeof key === 'string'
          ? key
          : JSON.stringify(key)
        )
      }
    },
    /**
     * hasKeysCache
     * 
     * @returns {(key: CryptoKey | JSONWEBKEY_STRING) => boolean}
     */
    get has() {
      return key => {
        if (key instanceof CryptoKey) {
          return this.jsonWebKeysCache.has(key)
        }
        return this.cryptoKeysCache.has(typeof key === 'string'
          ? key
          : JSON.stringify(key)
        )
      }
    },
    /**
     * setKeysCache
     * 
     * @returns {(jsonWebKey: JSONWEBKEY_STRING, cryptoKey: CryptoKey) => void}
     */
    get set() {
      return (jsonWebKey, cryptoKey) => {
        // @ts-ignore
        this.cryptoKeysCache.set(
          typeof jsonWebKey === 'string'
            ? jsonWebKey
            : JSON.stringify(jsonWebKey),
          cryptoKey
        )
        // @ts-ignore
        this.jsonWebKeysCache.set(
          cryptoKey, 
          typeof jsonWebKey === 'string'
            ? JSON.parse(jsonWebKey)
            : jsonWebKey
        )
      }
    }
  }

  /**
   * caching the cryptoKey derived from one public and one private key by the two jsonWebKeys as map-key
   *
   * @type {Map<string, KEY>}
   */
  static #derivedKeysCache = new Map()

  /**
   * caching the encrypted text by the jsonWebKey and plain text as map-key
   *
   * @type {Map<string, ENCRYPTED | ENCRYPTED_ERROR>}
   */
  static #encryptedCache = new Map()

  /**
   * caching the decrypted (plain) text by the jsonWebKey and encrypted text as map-key
   *
   * @type {Map<string, DECRYPTED | DECRYPTED_ERROR>}
   */
  static #decryptedCache = new Map()

  constructor (options = { separator: '<>' }) {
    super()

    this.separator = this.getAttribute('separator') || options.separator

    /**
     * Generate Key Event Listener
     *
     * @param {CustomEvent & {detail: {synchronous: boolean, jsonWebKey: boolean, resolve?: () => Promise<KEY | KEY_PAIR>}}} event
     * @return {any}
     */
    this.generateKeyEventListener = event => {
      this.respond(event.detail?.resolve, event.detail?.name || 'crypto-generated-key', event.detail?.synchronous
        ? event.detail?.jsonWebKey
          ? this.generateSyncJsonWebKey()
          : this.generateSyncKey()
        : event.detail?.jsonWebKey
          ? this.generateAsyncJsonWebKeyPair()
          : this.generateAsyncKeyPair()
      )
    }

    /**
     * Derive Key Event Listener
     *
     * @param {CustomEvent & {detail: {jsonWebKey: boolean, privateKey: KEY, publicKey: KEY, keyUsages: string[], resolve?: () => Promise<KEY | JSON_WEB_KEY_TO_CRYPTOKEY_ERROR>}}} event
     * @return {any}
     */
    this.deriveKeyEventListener = event => {
      this.respond(event.detail?.resolve, event.detail?.name || 'crypto-derived-key', event.detail?.jsonWebKey
        ? this.deriveSyncJsonWebKeyFromAsyncJsonWebKeyPair(event.detail.privateKey, event.detail.publicKey, event.detail.keyUsages)
        : this.deriveSyncKeyFromAsyncKeyPair(event.detail.privateKey, event.detail.publicKey, event.detail.keyUsages)
      )
    }

    /**
     * Encrypt Event Listener
     *
     * @param {CustomEvent & {detail: {jsonWebKey: boolean, text: string, key: KEY, resolve?: () => Promise<ENCRYPTED | JSON_WEB_KEY_TO_CRYPTOKEY_ERROR>}}} event
     * @return {any}
     */
    this.encryptEventListener = event => {
      this.respond(event.detail?.resolve, event.detail?.name || 'crypto-encrypted', event.detail?.jsonWebKey
        ? this.encryptWithJsonWebKey(event.detail.text, event.detail.key)
        : this.encrypt(event.detail.text, event.detail.key)
      )
    }

    /**
     * Decrypt Event Listener
     *
     * @param {CustomEvent & {detail: {jsonWebKey: boolean, encrypted: ENCRYPTED, key: KEY, resolve?: () => Promise<DECRYPTED | JSON_WEB_KEY_TO_CRYPTOKEY_ERROR>}}} event
     * @return {any}
     */
    this.decryptEventListener = event => {
      this.respond(event.detail?.resolve, event.detail?.name || 'crypto-decrypted', event.detail?.jsonWebKey
        ? this.decryptWithJsonWebKey(event.detail.encrypted, event.detail.key)
        : this.decrypt(event.detail.encrypted, event.detail.key)
      )
    }

    //await this.jsonWebKeyToCryptoKey(privateKey.jsonWebKey)
    /**
     * jsonWebKeyToCryptoKey Event Listener
     * user this to check the validity of the jsonWebKey
     *
     * @param {CustomEvent & {detail: {jsonWebKey: JsonWebKey, resolve?: () => Promise<CryptoKey|JSON_WEB_KEY_TO_CRYPTOKEY_ERROR>}}} event
     * @return {any}
     */
    this.jsonWebKeyToCryptoKeyEventListener = event => {
      this.respond(event.detail?.resolve, event.detail?.name || 'crypto-json-web-key-to-crypto-key', this.jsonWebKeyToCryptoKey(event.detail.jsonWebKey)
      )
    }
  }

  connectedCallback () {
    this.addEventListener(this.getAttribute('crypto-generate-key') || 'crypto-generate-key', this.generateKeyEventListener)
    this.addEventListener(this.getAttribute('crypto-derive-key') || 'crypto-derive-key', this.deriveKeyEventListener)
    this.addEventListener(this.getAttribute('crypto-encrypt') || 'crypto-encrypt', this.encryptEventListener)
    this.addEventListener(this.getAttribute('crypto-decrypt') || 'crypto-decrypt', this.decryptEventListener)
    this.addEventListener(this.getAttribute('crypto-get-json-web-key-to-crypto-key') || 'crypto-get-json-web-key-to-crypto-key', this.jsonWebKeyToCryptoKeyEventListener)
  }

  disconnectedCallback () {
    this.removeEventListener(this.getAttribute('crypto-generate-key') || 'crypto-generate-key', this.generateKeyEventListener)
    this.removeEventListener(this.getAttribute('crypto-derive-key') || 'crypto-derive-key', this.deriveKeyEventListener)
    this.removeEventListener(this.getAttribute('crypto-encrypt') || 'crypto-encrypt', this.encryptEventListener)
    this.removeEventListener(this.getAttribute('crypto-decrypt') || 'crypto-decrypt', this.decryptEventListener)
    this.removeEventListener(this.getAttribute('crypto-get-json-web-key-to-crypto-key') || 'crypto-get-json-web-key-to-crypto-key', this.jsonWebKeyToCryptoKeyEventListener)
  }

  /** ---generateSyncKey--- */
  /**
   * get new synchronous JsonWebKey
   * 
   * @async
   * @returns {Promise<KEY & {jsonWebKey: JSONWEBKEY_STRING}>}
   */
  async generateSyncJsonWebKey () {
    const key = await this.generateSyncKey()
    key.jsonWebKey = await this.cryptoKeyToJsonWebKey(key.cryptoKey)
    // @ts-ignore
    return key
  }
  /**
   * get new synchronous key
   * 
   * @async
   * @returns {Promise<KEY>}
   */
  async generateSyncKey () {
    return this.webWorker(Crypto.#_generateSyncKey, Crypto.#epochDateNow)
  }
  /**
   * get new synchronous key
   * 
   * @async
   * @static
   * @param {string} epoch
   * @returns {Promise<KEY>}
   */
  static async #_generateSyncKey (epoch) {
    return {
      cryptoKey: await self.crypto.subtle.generateKey(
        {
          name: 'AES-GCM',
          length: 256
        },
        true,
        ['encrypt', 'decrypt']
      ),
      epoch
    }
  }

  /** ---generateAsyncKeyPair--- */
  /**
   * get new asynchronous JsonWebKey pair
   * 
   * @async
   * @returns {Promise<KEY_PAIR>}
   */
  async generateAsyncJsonWebKeyPair () {
    const keys = await this.generateAsyncKeyPair()
    keys.publicKey.jsonWebKey = await this.cryptoKeyToJsonWebKey(keys.publicKey.cryptoKey)
    keys.privateKey.jsonWebKey = await this.cryptoKeyToJsonWebKey(keys.privateKey.cryptoKey)
    // @ts-ignore
    return keys
  }
  /**
   * get new asynchronous key pair
   * 
   * @async
   * @returns {Promise<KEY_PAIR>}
   */
  async generateAsyncKeyPair () {
    return this.webWorker(Crypto.#_generateAsyncKeyPair, Crypto.#epochDateNow)
  }
  /**
   * get new asynchronous key pair
   * 
   * @async
   * @static
   * @param {string} epoch
   * @returns {Promise<KEY_PAIR>}
   */
  static async #_generateAsyncKeyPair (epoch) {
    const {publicKey, privateKey} = await self.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveKey', 'deriveBits']
    )
    return {
      publicKey: {
        cryptoKey: publicKey,
        epoch
      },
      privateKey: {
        cryptoKey: privateKey,
        epoch
      }
    }
  }

  /** ---deriveSyncKeyFromAsyncKeyPair--- */
  /**
   * deriveSyncKeyFromAsyncKeyPair JsonWebKeys
   * typically created with own privateKey and foreign publicKey
   * creates the same key with own privateKey and foreign publicKey as with own publicKey and foreign privateKey
   * 
   * @async
   * @param {KEY & {jsonWebKey: JSONWEBKEY_STRING}} privateKey
   * @param {KEY & {jsonWebKey: JSONWEBKEY_STRING}} publicKey
   * @param {KeyUsage[]} [keyUsages=['encrypt', 'decrypt']]
   * @returns {Promise<KEY & {jsonWebKey: JSONWEBKEY_STRING}|JSON_WEB_KEY_TO_CRYPTOKEY_ERROR>}
   */
  async deriveSyncJsonWebKeyFromAsyncJsonWebKeyPair (privateKey, publicKey, keyUsages = ['encrypt', 'decrypt']) {
    const mapKey = privateKey.jsonWebKey && publicKey.jsonWebKey
      ? `${typeof privateKey.jsonWebKey === 'string' ? privateKey.jsonWebKey : JSON.stringify(privateKey.jsonWebKey)}${this.separator}${typeof publicKey.jsonWebKey === 'string' ? publicKey.jsonWebKey : JSON.stringify(publicKey.jsonWebKey)}`
      : null
    // @ts-ignore
    if (mapKey && Crypto.#derivedKeysCache.has(mapKey)) return Crypto.#derivedKeysCache.get(mapKey)
    if (!(privateKey.cryptoKey instanceof CryptoKey)) {
      // @ts-ignore
      privateKey.cryptoKey = await this.jsonWebKeyToCryptoKey(privateKey.jsonWebKey)
      // @ts-ignore
      if (privateKey.cryptoKey.error) return privateKey.cryptoKey
    }
    if (!(publicKey.cryptoKey instanceof CryptoKey)) {
      // @ts-ignore
      publicKey.cryptoKey = await this.jsonWebKeyToCryptoKey(publicKey.jsonWebKey)
      // @ts-ignore
      if (publicKey.cryptoKey.error) return publicKey.cryptoKey
    }
    const cryptoKey = await this.deriveSyncKeyFromAsyncKeyPair(privateKey, publicKey, keyUsages)
    // @ts-ignore
    if (cryptoKey.error) return cryptoKey
    // @ts-ignore
    cryptoKey.jsonWebKey = await this.cryptoKeyToJsonWebKey(cryptoKey.cryptoKey)
    // @ts-ignore
    if (mapKey) Crypto.#derivedKeysCache.set(mapKey, cryptoKey)
    // @ts-ignore
    return cryptoKey
  }
  /**
   * deriveSyncKeyFromAsyncKeyPair
   * typically created with own privateKey and foreign publicKey
   * creates the same key with own privateKey and foreign publicKey as with own publicKey and foreign privateKey
   * 
   * @async
   * @param {KEY} privateKey
   * @param {KEY} publicKey
   * @param {KeyUsage[]} [keyUsages=['encrypt', 'decrypt']]
   * @returns {Promise<KEY|DERIVE_ERROR>}
   */
  async deriveSyncKeyFromAsyncKeyPair (privateKey, publicKey, keyUsages = ['encrypt', 'decrypt']) {
    return this.webWorker(Crypto.#_deriveSyncKeyFromAsyncKeyPair, privateKey, publicKey, keyUsages, Crypto.#epochDateNow)
  }
  /**
   * deriveSyncKeyFromAsyncKeyPair
   * typically created with own privateKey and foreign publicKey
   * creates the same key with own privateKey and foreign publicKey as with own publicKey and foreign privateKey
   * 
   * @async
   * @static
   * @param {KEY} privateKey
   * @param {KEY} publicKey
   * @param {KeyUsage[]} keyUsages
   * @param {string} epoch
   * @returns {Promise<KEY|DERIVE_ERROR>}
   */
  static async #_deriveSyncKeyFromAsyncKeyPair (privateKey, publicKey, keyUsages, epoch) {
    try {
      return {
        cryptoKey: await self.crypto.subtle.deriveKey(
          { 
            name: 'ECDH',
            public: publicKey.cryptoKey
          },
          privateKey.cryptoKey,
          {
            name: 'AES-GCM',
            length: 256
          },
          true,
          keyUsages
        ),
        epoch,
        derived: {
          privateKeyEpoch: privateKey.epoch,
          publicKeyEpoch: publicKey.epoch
        }
      }
    } catch (error) {
      return {
        error: true,
        message: `Error deriving sync key from async key pair: ${error}`,
        privateKey,
        publicKey
      }
    }
  }

  /** ---encrypt--- */
  /**
   * encrypt by JsonWebKeys
   * 
   * @async
   * @param {string} text
   * @param {KEY & {jsonWebKey: JSONWEBKEY_STRING}} key
   * @returns {Promise<ENCRYPTED | ENCRYPTED_ERROR | JSON_WEB_KEY_TO_CRYPTOKEY_ERROR>}
   */
  async encryptWithJsonWebKey (text, key) {
    const mapKey = key.jsonWebKey
      ? `${text}${this.separator}${typeof key.jsonWebKey === 'string' ? key.jsonWebKey : JSON.stringify(key.jsonWebKey)}`
      : null
    // @ts-ignore
    if (mapKey && Crypto.#encryptedCache.has(mapKey)) return Crypto.#encryptedCache.get(mapKey)
    if (!(key.cryptoKey instanceof CryptoKey)) {
      // @ts-ignore
      key.cryptoKey = await this.jsonWebKeyToCryptoKey(key.jsonWebKey)
      // @ts-ignore
      if (key.cryptoKey.error) return key.cryptoKey
    }
    const encrypted = await this.encrypt(text, key)
    if (mapKey) Crypto.#encryptedCache.set(mapKey, encrypted)
    return encrypted
  }
  /**
   * encrypt
   * 
   * @async
   * @param {string} text
   * @param {KEY} key
   * @returns {Promise<ENCRYPTED|ENCRYPTED_ERROR>}
   */
  async encrypt (text, key) {
    return this.webWorker(Crypto.#_encrypt, text, key, Crypto.#epochDateNow)
  }
  /**
   * encrypt
   * 
   * @async
   * @static
   * @param {string} text
   * @param {KEY} key
   * @param {string} epoch
   * @returns {Promise<ENCRYPTED|ENCRYPTED_ERROR>}
   */
  static async #_encrypt (text, key, epoch) {
    const name = 'AES-GCM'
    // IV should be 96 bits long [96 bits / 8 = 12 bytes] and unique for each encryption (https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams#iv)
    const iv = self.crypto.getRandomValues(new Uint8Array(12))
    try {
      return {
        text: btoa(String.fromCharCode(...new Uint8Array(await self.crypto.subtle.encrypt(
          {
            name,
            iv
          },
          key.cryptoKey,
          new TextEncoder().encode(JSON.stringify({
            text,
            epoch
          }))
        )))),
        iv,
        name,
        key: {
          epoch: key.epoch,
          derived: key.derived
        }
      }
    }  catch (error) {
      return {
        error: true,
        message: `Error encrypting text: ${error}`,
        text,
        key
      }
    }
  }

  /** ---decrypt--- */
  /**
   * decrypt by JsonWebKeys
   * 
   * @async
   * @param {ENCRYPTED} encrypted
   * @param {KEY & {jsonWebKey: JSONWEBKEY_STRING}} key
   * @returns {Promise<DECRYPTED|DECRYPTED_ERROR|JSON_WEB_KEY_TO_CRYPTOKEY_ERROR>}
   */
  async decryptWithJsonWebKey (encrypted, key) {
    if (!(encrypted.iv instanceof Uint8Array) && typeof encrypted.iv === 'object') encrypted.iv = new Uint8Array(Object.values(encrypted.iv))
    const mapKey = key.jsonWebKey
      ? `${encrypted.text}${this.separator}${encrypted.iv}${this.separator}${typeof key.jsonWebKey === 'string' ? key.jsonWebKey : JSON.stringify(key.jsonWebKey)}`
      : null
    // @ts-ignore
    if (mapKey && Crypto.#decryptedCache.has(mapKey)) return Crypto.#decryptedCache.get(mapKey)
    if (!(key.cryptoKey instanceof CryptoKey)) {
      // @ts-ignore
      key.cryptoKey = await this.jsonWebKeyToCryptoKey(key.jsonWebKey)
      // @ts-ignore
      if (key.cryptoKey.error) return key.cryptoKey
    }
    const decrypted = await this.decrypt(encrypted, key)
    if (mapKey) Crypto.#decryptedCache.set(mapKey, decrypted)
    return decrypted
  }
  /**
   * decrypt
   * 
   * @async
   * @param {ENCRYPTED} encrypted
   * @param {KEY} key
   * @returns {Promise<DECRYPTED|DECRYPTED_ERROR>}
   */
  async decrypt (encrypted, key) {
    return this.webWorker(Crypto.#_decrypt, encrypted, key, Crypto.#epochDateNow)
  }
  /**
   * decrypt
   * 
   * @async
   * @static
   * @param {ENCRYPTED} encrypted
   * @param {KEY} key
   * @param {string} epoch
   * @returns {Promise<DECRYPTED|DECRYPTED_ERROR>}
   */
  static async #_decrypt (encrypted, key, epoch) {
    if (!(encrypted.iv instanceof Uint8Array)) return {
      error: true,
      message: 'Error decrypting; iv not as Uint8Array supplied!',
      encrypted,
      key
    }
    try {
      const decrypted = JSON.parse(new TextDecoder().decode(await self.crypto.subtle.decrypt(
        {
          name: encrypted.name,
          iv: encrypted.iv
        },
        key.cryptoKey,
        Uint8Array.from(atob(encrypted.text), char => char.charCodeAt(0))
      )))
      if (!decrypted.text || !decrypted.epoch) throw new Error(`JSON with property text was expected at encrypted text! Only decrypt strings which were encrypted with this class. | ${JSON.stringify(decrypted)}`)
      return {
        text: decrypted.text,
        epoch,
        encrypted: {
          epoch: decrypted.epoch,
          key: encrypted.key
        },
        key: {
          epoch: key.epoch,
          derived: key.derived
        }
      }
    } catch (error) {
      return {
        error: true,
        message: `Error decrypting encrypted: ${error}`,
        encrypted,
        key
      }
    }
  }

  /** ---jsonWebKeyToCryptoKey + cryptoKeyToJsonWebKey--- */
  /**
   * jsonWebKeyToCryptoKey
   * 
   * @async
   * @param {JSONWEBKEY_STRING} jsonWebKey
   * @param {AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm | null} [algorithm=null]
   * @param {ReadonlyArray<KeyUsage> | null} [keyUsages=null]
   * @param {'jwk'} [format='jwk']
   * @returns {Promise<CryptoKey|JSON_WEB_KEY_TO_CRYPTOKEY_ERROR>}
   */
  async jsonWebKeyToCryptoKey (jsonWebKey, algorithm = null, keyUsages = null, format = 'jwk') {
    // @ts-ignore
    if (Crypto.#jsonWebCryptoKeysCache.has(jsonWebKey)) return Crypto.#jsonWebCryptoKeysCache.get(jsonWebKey)
    const cryptoKey = await this.webWorker(Crypto.#_jsonWebKeyToCryptoKey, jsonWebKey, algorithm, keyUsages, format)
    Crypto.#jsonWebCryptoKeysCache.set(jsonWebKey, cryptoKey)
    return cryptoKey
  }
  /**
   * jsonWebKeyToCryptoKey
   * 
   * @async
   * @static
   * @param {JsonWebKey} jsonWebKey
   * @param {AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm | null} algorithm
   * @param {ReadonlyArray<KeyUsage> | null} keyUsages
   * @param {'jwk'} format
   * @returns {Promise<CryptoKey|JSON_WEB_KEY_TO_CRYPTOKEY_ERROR>}
   */
  static async #_jsonWebKeyToCryptoKey (jsonWebKey, algorithm, keyUsages, format) {
    if (!jsonWebKey) return {
      error: true,
      message: `Error missing JsonWebKey!`,
      jsonWebKey
    }
    if (typeof jsonWebKey === 'string') jsonWebKey = JSON.parse(jsonWebKey)
    if (!algorithm) {
      algorithm = {
        name: jsonWebKey.kty === 'oct'
          ? 'AES-GCM'
          : jsonWebKey.kty === 'EC'
            ? 'ECDH'
            : jsonWebKey.kty || 'AES-GCM',
      }
      if (algorithm.name === 'AES-GCM') {
        // @ts-ignore
        algorithm.length = 256
      } else {
        // @ts-ignore
        algorithm.namedCurve = jsonWebKey.crv || 'P-256'
      }
    }
    try {
      return await self.crypto.subtle.importKey(
        // @ts-ignore
        format,
        jsonWebKey,
        algorithm,
        true,
        keyUsages
          ? keyUsages
          : jsonWebKey.key_ops || []
      )
    } catch (error) {
      return {
        error: true,
        message: `Error import JsonWebKey: ${error}`,
        jsonWebKey
      }
    }
  }
  /**
   * cryptoKeyToJsonWebKey
   * 
   * @async
   * @param {CryptoKey} cryptoKey
   * @param {'jwk'} [format='jwk']
   * @returns {Promise<JsonWebKey>}
   */
  async cryptoKeyToJsonWebKey (cryptoKey, format = 'jwk') {
    // @ts-ignore
    if (Crypto.#jsonWebCryptoKeysCache.has(cryptoKey)) return Crypto.#jsonWebCryptoKeysCache.get(cryptoKey)
    const jsonWebKey = Object.freeze(await this.webWorker(Crypto.#_cryptoKeyToJsonWebKey, cryptoKey, format))
    Crypto.#jsonWebCryptoKeysCache.set(jsonWebKey, cryptoKey)
    return jsonWebKey
  }
  /**
   * cryptoKeyToJsonWebKey
   * 
   * @async
   * @static
   * @param {CryptoKey} cryptoKey
   * @param {'jwk'} format
   * @returns {Promise<JsonWebKey>}
   */
  static async #_cryptoKeyToJsonWebKey (cryptoKey, format) {
    return await self.crypto.subtle.exportKey(format, cryptoKey)
  }

  /** ---other--- */
  /**
   * @static
   * @return {string}
   */
  static get #epochDateNow () {
    return JSON.stringify({ epoch: Date.now(), uuid: self.crypto.randomUUID() })
  }

  /**
   * @param {(any)=>void} resolve
   * @param {string|undefined} name
   * @param {any} detail
   * @return {void | any}
   */
  respond (resolve, name, detail) {
    if (typeof resolve === 'function') return resolve(detail)
    if (typeof name === 'string') {
      this.dispatchEvent(new CustomEvent(name, {
        detail,
        bubbles: true,
        cancelable: true,
        composed: true
      }))
    }
  }
}
