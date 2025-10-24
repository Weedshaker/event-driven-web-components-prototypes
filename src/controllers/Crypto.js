// @ts-check

import { WebWorker } from '../WebWorker.js'

/** @typedef {{ cryptoKey: CryptoKey, jsonWebKey?: JsonWebKey, epoch: string, derived?: { privateKeyEpoch: string, publicKeyEpoch: string } }} KEY */
/** @typedef {{ text: string, iv: Uint8Array<ArrayBuffer>, name: string, epoch: string, keyEpoch: string }} ENCRYPTED */
/** @typedef {{ text: string, epoch: string, keyEpoch: string, encrypted: { epoch: string, keyEpoch: string } }} DECRYPTED */

/**
 * As a controller, this component becomes a crypto manager and organizes events
 * Inspired by: https://github.com/mdn/dom-examples/blob/main/web-crypto/derive-key/ecdh.js + https://getstream.io/blog/web-crypto-api-chat/
 *
 * @export
 * @class Crypto
 */
export default class Crypto extends WebWorker() {
  static #keysCache = {
    /**
     * caching the cryptoKeys by jsonWebKey as map-key
     *
     * @type {Map<string, CryptoKey>}
     */
    cryptoKeysCache: new Map(),
    /**
     * caching the jsonWebKey by cryptoKey as map-key
     *
     * @type {WeakMap<CryptoKey, JsonWebKey>}
     */
    jsonWebKeysCache: new WeakMap(),
    /**
     * getKeysCache
     * 
     * @returns {(key: CryptoKey | JsonWebKey | string) => CryptoKey | JsonWebKey | undefined}
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
     * @returns {(key: CryptoKey | JsonWebKey | string) => boolean}
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
     * @returns {(jsonWebKey: JsonWebKey | string, cryptoKey: CryptoKey) => void}
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

  constructor () {
    super()

    this.startExample()
  }

  async startExample () {
    this.bobsAsyncKeyPair = await this.generateAsyncKeyPair()
    this.alicesAsyncKeyPair = await this.generateAsyncKeyPair()

    this.bobToAliceAsyncKey = await this.deriveSyncKeyFromAsyncKeyPair(this.bobsAsyncKeyPair.privateKey, this.alicesAsyncKeyPair.publicKey)
    this.aliceToBobAsyncKey = await this.deriveSyncKeyFromAsyncKeyPair(this.alicesAsyncKeyPair.privateKey, this.bobsAsyncKeyPair.publicKey)

    const encryptedBobToAlice = await this.encrypt('Hello Alice', this.bobToAliceAsyncKey)
    const encryptedAliceToBob = await this.encrypt('Hello Bob', this.aliceToBobAsyncKey)

    const decryptedBobToAlice = await this.decrypt(encryptedBobToAlice, this.aliceToBobAsyncKey)
    const decryptedAliceToBob = await this.decrypt(encryptedAliceToBob, this.bobToAliceAsyncKey)

    console.log('*********', {encryptedBobToAlice, encryptedAliceToBob, decryptedBobToAlice, decryptedAliceToBob})

    // TODO: Example of the jwk functions
    // TODO: EventDriven analog Storage.js
    // TODO: UI for examples
  }

  connectedCallback () {
    
  }

  disconnectedCallback () {
    
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
      keyEpoch: key.epoch
    }
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
        keyEpoch: key.epoch,
        encrypted: {
          epoch: encrypted.epoch,
          keyEpoch: encrypted.keyEpoch
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
   * @param {JsonWebKey | string} jsonWebKey
   * @param {AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm | null} [algorithm=null]
   * @param {ReadonlyArray<KeyUsage> | null} [keyUsages=null]
   * @param {'jwk'} [format='jwk']
   * @returns {Promise<CryptoKey>}
   */
  async jsonWebKeyToCryptoKey (jsonWebKey, algorithm = null, keyUsages = null, format = 'jwk') {
    // @ts-ignore
    if (Crypto.#keysCache.has(jsonWebKey)) return Crypto.#keysCache.get(jsonWebKey)
    const cryptoKey = await this.webWorker(Crypto.#_jsonWebKeyToCryptoKey, jsonWebKey, algorithm, keyUsages, format)
    Crypto.#keysCache.set(jsonWebKey, cryptoKey)
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
    if (Crypto.#keysCache.has(cryptoKey)) return Crypto.#keysCache.get(cryptoKey)
    const jsonWebKey = await this.webWorker(Crypto.#_cryptoKeyToJsonWebKey, cryptoKey, format)
    Crypto.#keysCache.set(jsonWebKey, cryptoKey)
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
