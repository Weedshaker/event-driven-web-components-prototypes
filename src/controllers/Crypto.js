// @ts-check

import { WebWorker } from '../WebWorker.js'

/** @typedef {{ privateKeyEpoch: string, publicKeyEpoch: string }} DERIVED_KEY */
/** @typedef {{ epoch:string, derived?: DERIVED_KEY }} KEY_EPOCH */
/** @typedef {JsonWebKey | string} JSONWEBKEY_STRING */
/** @typedef {{ cryptoKey: CryptoKey, jsonWebKey?: JSONWEBKEY_STRING | string, epoch: string, derived?: DERIVED_KEY }} KEY */
/** @typedef {{ text: string, iv: Uint8Array<ArrayBuffer>, name: string, epoch: string, key: KEY_EPOCH }} ENCRYPTED */
/** @typedef {{ text: string, epoch: string, encrypted: { epoch: string, key: KEY_EPOCH }, key: KEY_EPOCH }} DECRYPTED */

/**
 * As a controller, this component becomes a crypto manager and organizes events
 * Inspired by: https://github.com/mdn/dom-examples/blob/main/web-crypto/derive-key/ecdh.js + https://getstream.io/blog/web-crypto-api-chat/
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
   * @type {Map<string, ENCRYPTED>}
   */
  static #encryptedCache = new Map()

  /**
   * caching the decrypted (plain) text by the jsonWebKey and encrypted text as map-key
   *
   * @type {Map<string, DECRYPTED>}
   */
  static #decryptedCache = new Map()

  constructor (options = { separator: '<>' }) {
    super()

    this.separator = this.getAttribute('separator') || options.separator
    this.startExample()
  }

  async startExample () {
    console.log('****caches*****', {
      derivedKeysCache: Crypto.#derivedKeysCache, 
      encryptedCache: Crypto.#encryptedCache,
      decryptedCache: Crypto.#decryptedCache,
      jsonWebCryptoKeysCache: Crypto.#jsonWebCryptoKeysCache
    })
    const bobsAsyncJsonWebKeyPair = await this.generateAsyncJsonWebKeyPair()
    const alicesAsyncJsonWebKeyPair = await this.generateAsyncJsonWebKeyPair()

    const bobToAliceAsyncJsonWebKey = await this.deriveSyncJsonWebKeyFromAsyncJsonWebKeyPair(bobsAsyncJsonWebKeyPair.privateKey, alicesAsyncJsonWebKeyPair.publicKey)
    const aliceToBobAsyncJsonWebKey = await this.deriveSyncJsonWebKeyFromAsyncJsonWebKeyPair(alicesAsyncJsonWebKeyPair.privateKey, bobsAsyncJsonWebKeyPair.publicKey)

    const encryptedBobToAlice = await this.encryptWithJsonWebKey('Hello Alice', bobToAliceAsyncJsonWebKey)
    const encryptedAliceToBob = await this.encryptWithJsonWebKey('Hello Bob', aliceToBobAsyncJsonWebKey)

    const decryptedBobToAlice = await this.decryptWithJsonWebKey(encryptedBobToAlice, aliceToBobAsyncJsonWebKey)
    const decryptedAliceToBob = await this.decryptWithJsonWebKey(encryptedAliceToBob, bobToAliceAsyncJsonWebKey)

    console.log('*********', {encryptedBobToAlice, encryptedAliceToBob, decryptedBobToAlice, decryptedAliceToBob})

    // TODO: EventDriven analog Storage.js
  }

  connectedCallback () {
    
  }

  disconnectedCallback () {
    
  }

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

  /**
   * get new asynchronous JsonWebKey pair
   * 
   * @async
   * @returns {Promise<{ publicKey: KEY & {jsonWebKey: JSONWEBKEY_STRING}, privateKey: KEY & {jsonWebKey: JSONWEBKEY_STRING} }>}
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
   * @returns {Promise<{ publicKey: KEY, privateKey: KEY }>}
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
   * @returns {Promise<{ publicKey: KEY, privateKey: KEY }>}
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

  /**
   * deriveSyncKeyFromAsyncKeyPair JsonWebKeys
   * typically created with own privateKey and foreign publicKey
   * 
   * @async
   * @param {KEY & {jsonWebKey: JSONWEBKEY_STRING}} privateKey
   * @param {KEY & {jsonWebKey: JSONWEBKEY_STRING}} publicKey
   * @param {KeyUsage[]} [keyUsages=['encrypt', 'decrypt']]
   * @returns {Promise<KEY & {jsonWebKey: JSONWEBKEY_STRING}>}
   */
  async deriveSyncJsonWebKeyFromAsyncJsonWebKeyPair (privateKey, publicKey, keyUsages = ['encrypt', 'decrypt']) {
    const mapKey = `${typeof privateKey.jsonWebKey === 'string' ? privateKey.jsonWebKey : JSON.stringify(privateKey.jsonWebKey)}${this.separator}${typeof publicKey.jsonWebKey === 'string' ? publicKey.jsonWebKey : JSON.stringify(publicKey.jsonWebKey)}`
    // @ts-ignore
    if (Crypto.#derivedKeysCache.has(mapKey)) return Crypto.#derivedKeysCache.get(mapKey)
    if (!privateKey.cryptoKey) privateKey.cryptoKey = await this.jsonWebKeyToCryptoKey(privateKey.jsonWebKey)
    if (!publicKey.cryptoKey) publicKey.cryptoKey = await this.jsonWebKeyToCryptoKey(publicKey.jsonWebKey)
    const cryptoKey = await this.deriveSyncKeyFromAsyncKeyPair(privateKey, publicKey, keyUsages)
    cryptoKey.jsonWebKey = await this.cryptoKeyToJsonWebKey(cryptoKey.cryptoKey)
    Crypto.#derivedKeysCache.set(mapKey, cryptoKey)
    // @ts-ignore
    return cryptoKey
  }

  /**
   * deriveSyncKeyFromAsyncKeyPair
   * typically created with own privateKey and foreign publicKey
   * 
   * @async
   * @param {KEY} privateKey
   * @param {KEY} publicKey
   * @param {KeyUsage[]} [keyUsages=['encrypt', 'decrypt']]
   * @returns {Promise<KEY>}
   */
  async deriveSyncKeyFromAsyncKeyPair (privateKey, publicKey, keyUsages = ['encrypt', 'decrypt']) {
    return this.webWorker(Crypto.#_deriveSyncKeyFromAsyncKeyPair, privateKey, publicKey, keyUsages, Crypto.#epochDateNow)
  }

  /**
   * deriveSyncKeyFromAsyncKeyPair
   * typically created with own privateKey and foreign publicKey
   * 
   * @async
   * @static
   * @param {KEY} privateKey
   * @param {KEY} publicKey
   * @param {KeyUsage[]} keyUsages
   * @param {string} epoch
   * @returns {Promise<KEY>}
   */
  static async #_deriveSyncKeyFromAsyncKeyPair (privateKey, publicKey, keyUsages, epoch) {
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
  }

  /**
   * encrypt by JsonWebKeys
   * 
   * @async
   * @param {string} text
   * @param {KEY & {jsonWebKey: JSONWEBKEY_STRING}} key
   * @returns {Promise<ENCRYPTED>}
   */
  async encryptWithJsonWebKey (text, key) {
    const mapKey = `${text}${this.separator}${typeof key.jsonWebKey === 'string' ? key.jsonWebKey : JSON.stringify(key.jsonWebKey)}`
    // @ts-ignore
    if (Crypto.#encryptedCache.has(mapKey)) return Crypto.#encryptedCache.get(mapKey)
    if (!key.cryptoKey) key.cryptoKey = await this.jsonWebKeyToCryptoKey(key.jsonWebKey)
    const encrypted = await this.webWorker(Crypto.#_encrypt, text, key, Crypto.#epochDateNow)
    Crypto.#encryptedCache.set(mapKey, encrypted)
    return encrypted
  }

  /**
   * encrypt
   * 
   * @async
   * @param {string} text
   * @param {KEY} key
   * @returns {Promise<ENCRYPTED>}
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
   * @returns {Promise<ENCRYPTED>}
   */
  static async #_encrypt (text, key, epoch) {
    const name = 'AES-GCM'
    // IV should be 96 bits long [96 bits / 8 = 12 bytes] and unique for each encryption (https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams#iv)
    const iv = self.crypto.getRandomValues(new Uint8Array(12))
    return {
      text: btoa(String.fromCharCode(...new Uint8Array(await self.crypto.subtle.encrypt(
        {
          name,
          iv
        },
        key.cryptoKey,
        new TextEncoder().encode(text)
      )))),
      iv,
      name,
      epoch,
      key: {
        epoch: key.epoch,
        derived: key.derived
      }
    }
  }

  /**
   * decrypt by JsonWebKeys
   * 
   * @async
   * @param {ENCRYPTED} encrypted
   * @param {KEY & {jsonWebKey: JSONWEBKEY_STRING}} key
   * @returns {Promise<ENCRYPTED>}
   */
  async decryptWithJsonWebKey (encrypted, key) {
    const mapKey = `${encrypted.text}${this.separator}${encrypted.iv}${this.separator}${typeof key.jsonWebKey === 'string' ? key.jsonWebKey : JSON.stringify(key.jsonWebKey)}`
    // @ts-ignore
    if (Crypto.#decryptedCache.has(mapKey)) return Crypto.#decryptedCache.get(mapKey)
    if (!key.cryptoKey) key.cryptoKey = await this.jsonWebKeyToCryptoKey(key.jsonWebKey)
    const decrypted = await this.webWorker(Crypto.#_decrypt, encrypted, key, Crypto.#epochDateNow)
    Crypto.#decryptedCache.set(mapKey, decrypted)
    return decrypted
  }

  /**
   * decrypt
   * 
   * @async
   * @param {ENCRYPTED} encrypted
   * @param {KEY} key
   * @returns {Promise<DECRYPTED|{ error: true, message: string, encrypted: ENCRYPTED, key: KEY }>}
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
   * @returns {Promise<DECRYPTED|{ error: true, message: string, encrypted: ENCRYPTED, key: KEY }>}
   */
  static async #_decrypt (encrypted, key, epoch) {
    try {
      return {
        text: new TextDecoder().decode(await self.crypto.subtle.decrypt(
          {
            name: encrypted.name,
            iv: encrypted.iv
          },
          key.cryptoKey,
          Uint8Array.from(atob(encrypted.text), char => char.charCodeAt(0))
        )),
        epoch,
        encrypted: {
          epoch: encrypted.epoch,
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
        message: `error decrypting encrypted: ${error}`,
        encrypted,
        key
      }
    }
  }

  /**
   * jsonWebKeyToCryptoKey
   * 
   * @async
   * @param {JSONWEBKEY_STRING} jsonWebKey
   * @param {AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm | null} [algorithm=null]
   * @param {ReadonlyArray<KeyUsage> | null} [keyUsages=null]
   * @param {'jwk'} [format='jwk']
   * @returns {Promise<CryptoKey>}
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
   * @returns {Promise<CryptoKey>}
   */
  static async #_jsonWebKeyToCryptoKey (jsonWebKey, algorithm, keyUsages, format) {
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
    const jsonWebKey = await this.webWorker(Crypto.#_cryptoKeyToJsonWebKey, cryptoKey, format)
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
