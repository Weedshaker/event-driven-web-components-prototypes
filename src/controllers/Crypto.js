// @ts-check

import { WebWorker } from '../WebWorker.js'

/**
 * As a controller, this component becomes a crypto manager and organizes events
 * Inspired by: https://github.com/mdn/dom-examples/blob/main/web-crypto/derive-key/ecdh.js + https://getstream.io/blog/web-crypto-api-chat/
 *
 * @export
 * @class Crypto
 */
export default class Crypto extends WebWorker() {
  /** @type {'jwk'} */
  #format = 'jwk'
  // IV should be 96 bits long [96 bits / 8 = 12 bytes] and unique for each encryption (https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams#iv)
  // TODO: Make it unique for each encryption and decryption. Can be publicly shared with encrypted message in plain.
  #iv = self.crypto.getRandomValues(new Uint8Array(12))

  constructor () {
    super()

    this.startExample()
  }

  async startExample () {
    this.bobsAsyncKeyPairJwk = await this.#getAsyncKeyPairJwk()
    this.alicesAsyncKeyPairJwk = await this.#getAsyncKeyPairJwk()
  
    this.bobsWithAlicesAsyncKey = await this.getAsyncKey(this.bobsAsyncKeyPairJwk.privateKeyJwk, this.alicesAsyncKeyPairJwk.publicKeyJwk)
    this.alicesWithBobsAsyncKey = await this.getAsyncKey(this.alicesAsyncKeyPairJwk.privateKeyJwk, this.bobsAsyncKeyPairJwk.publicKeyJwk)

    console.log('*********', this.bobsAsyncKeyPairJwk, this.alicesAsyncKeyPairJwk)
    let encryptedText
    console.log('encrypted: ', '"hello alice" to: ', (encryptedText = await this.encrypt('hello alice', this.bobsWithAlicesAsyncKey)))
    console.log('decrypted: ', `${encryptedText} to: `, await this.decrypt(encryptedText, this.alicesWithBobsAsyncKey))
    console.log('----------------------------')
    console.log('encrypted: ', '"hello bob" to: ', (encryptedText = await this.encrypt('hello bob', this.alicesWithBobsAsyncKey)))
    console.log('decrypted: ', `${encryptedText} to: `, await this.decrypt(encryptedText, this.bobsWithAlicesAsyncKey))
    console.log('----------------------------')

    this.rudisSyncKeyJwk = await this.#getSyncKeyJwk()
    console.log('*********', this.rudisSyncKeyJwk)
    this.rudisSyncKey = await this.getSyncKey(this.rudisSyncKeyJwk)
    console.log('encrypted: ', '"I am Rudi" to: ', (encryptedText = await this.encrypt('I am Rudi', this.rudisSyncKey)))
    console.log('decrypted: ', `${encryptedText} to: `, await this.decrypt(encryptedText, this.rudisSyncKey))
  }

  connectedCallback () {
    
  }

  disconnectedCallback () {
    
  }

  // synchronous key
  async #getSyncKeyJwk () {
    return await self.crypto.subtle.exportKey(
      this.#format,
      await self.crypto.subtle.generateKey(
        {
          name: 'AES-GCM',
          length: 256
        },
        true,
        ['encrypt', 'decrypt']
      )
    )
  }

  /**
   * getSyncKey
   * typically the 
   * 
   * @param {JsonWebKey} keyJwk
   * @returns {Promise<CryptoKey>}
   */
  async getSyncKey (keyJwk) {
    // Note: That self.crypto.subtle.deriveKey returns the same CryptoKey when same Jwks were used
    return await self.crypto.subtle.importKey(
          // @ts-ignore
          this.#format,
          keyJwk,
          {
            name: keyJwk.kty === 'oct' ? 'AES-GCM' : keyJwk.kty || 'AES-GCM',
            length: 256
          },
          true,
          keyJwk.key_ops || []
        )
  }

  // asynchronous key pair
  async #getAsyncKeyPairJwk () {
    const keyPair = await self.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveKey', 'deriveBits']
    )
    return {
      publicKeyJwk: await self.crypto.subtle.exportKey(
        this.#format,
        keyPair.publicKey
      ),
      privateKeyJwk: await self.crypto.subtle.exportKey(
        this.#format,
        keyPair.privateKey
      )
    }
  }

  /**
   * getAsyncKey
   * typically created with own privateKeyJwk and foreign publicKeyJwk
   * 
   * @param {JsonWebKey} privateKeyJwk
   * @param {JsonWebKey} publicKeyJwk
   * @param {KeyUsage[]} keyUsages?
   * @returns {Promise<CryptoKey>}
   */
  async getAsyncKey (privateKeyJwk, publicKeyJwk, keyUsages = ['encrypt', 'decrypt']) {
    // Note: That self.crypto.subtle.deriveKey returns the same CryptoKey when same Jwks were used
    return await self.crypto.subtle.deriveKey(
      { 
        name: 'ECDH',
        public: await self.crypto.subtle.importKey(
          // @ts-ignore
          this.#format,
          publicKeyJwk,
          {
            name: publicKeyJwk.kty === 'EC' ? 'ECDH' : publicKeyJwk.kty || 'ECDH',
            namedCurve: publicKeyJwk.crv || 'P-256',
          },
          true,
          publicKeyJwk.key_ops || []
        )
      },
      await self.crypto.subtle.importKey(
        // @ts-ignore
        this.#format,
        privateKeyJwk,
        {
          name: privateKeyJwk.kty === 'EC' ? 'ECDH' : privateKeyJwk.kty || 'ECDH',
          namedCurve: privateKeyJwk.crv || 'P-256',
        },
        true,
        privateKeyJwk.key_ops || ['deriveKey', 'deriveBits']
      ),
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      keyUsages
    )
  }

  async encrypt (text, key, iv = this.#iv) {
    return btoa(String.fromCharCode(...new Uint8Array(await self.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv
      },
      key,
      new TextEncoder().encode(text)
    ))))
  }

  async decrypt (text, key, iv = this.#iv) {
    try {
      return new TextDecoder().decode(await self.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv
        },
        key,
        Uint8Array.from(atob(text), char => char.charCodeAt(0))
      ))
    } catch (error) {
      return `error decrypting message: ${error}`
    }
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
