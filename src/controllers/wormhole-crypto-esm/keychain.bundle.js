var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// wormhole-crypto/node_modules/base64-js/index.js
var require_base64_js = __commonJS({
  "wormhole-crypto/node_modules/base64-js/index.js"(exports) {
    "use strict";
    exports.byteLength = byteLength;
    exports.toByteArray = toByteArray;
    exports.fromByteArray = fromByteArray;
    var lookup = [];
    var revLookup = [];
    var Arr = typeof Uint8Array !== "undefined" ? Uint8Array : Array;
    var code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (i = 0, len = code.length; i < len; ++i) {
      lookup[i] = code[i];
      revLookup[code.charCodeAt(i)] = i;
    }
    var i;
    var len;
    revLookup["-".charCodeAt(0)] = 62;
    revLookup["_".charCodeAt(0)] = 63;
    function getLens(b64) {
      var len2 = b64.length;
      if (len2 % 4 > 0) {
        throw new Error("Invalid string. Length must be a multiple of 4");
      }
      var validLen = b64.indexOf("=");
      if (validLen === -1) validLen = len2;
      var placeHoldersLen = validLen === len2 ? 0 : 4 - validLen % 4;
      return [validLen, placeHoldersLen];
    }
    function byteLength(b64) {
      var lens = getLens(b64);
      var validLen = lens[0];
      var placeHoldersLen = lens[1];
      return (validLen + placeHoldersLen) * 3 / 4 - placeHoldersLen;
    }
    function _byteLength(b64, validLen, placeHoldersLen) {
      return (validLen + placeHoldersLen) * 3 / 4 - placeHoldersLen;
    }
    function toByteArray(b64) {
      var tmp;
      var lens = getLens(b64);
      var validLen = lens[0];
      var placeHoldersLen = lens[1];
      var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen));
      var curByte = 0;
      var len2 = placeHoldersLen > 0 ? validLen - 4 : validLen;
      var i2;
      for (i2 = 0; i2 < len2; i2 += 4) {
        tmp = revLookup[b64.charCodeAt(i2)] << 18 | revLookup[b64.charCodeAt(i2 + 1)] << 12 | revLookup[b64.charCodeAt(i2 + 2)] << 6 | revLookup[b64.charCodeAt(i2 + 3)];
        arr[curByte++] = tmp >> 16 & 255;
        arr[curByte++] = tmp >> 8 & 255;
        arr[curByte++] = tmp & 255;
      }
      if (placeHoldersLen === 2) {
        tmp = revLookup[b64.charCodeAt(i2)] << 2 | revLookup[b64.charCodeAt(i2 + 1)] >> 4;
        arr[curByte++] = tmp & 255;
      }
      if (placeHoldersLen === 1) {
        tmp = revLookup[b64.charCodeAt(i2)] << 10 | revLookup[b64.charCodeAt(i2 + 1)] << 4 | revLookup[b64.charCodeAt(i2 + 2)] >> 2;
        arr[curByte++] = tmp >> 8 & 255;
        arr[curByte++] = tmp & 255;
      }
      return arr;
    }
    function tripletToBase64(num) {
      return lookup[num >> 18 & 63] + lookup[num >> 12 & 63] + lookup[num >> 6 & 63] + lookup[num & 63];
    }
    function encodeChunk(uint8, start, end) {
      var tmp;
      var output = [];
      for (var i2 = start; i2 < end; i2 += 3) {
        tmp = (uint8[i2] << 16 & 16711680) + (uint8[i2 + 1] << 8 & 65280) + (uint8[i2 + 2] & 255);
        output.push(tripletToBase64(tmp));
      }
      return output.join("");
    }
    function fromByteArray(uint8) {
      var tmp;
      var len2 = uint8.length;
      var extraBytes = len2 % 3;
      var parts = [];
      var maxChunkLength = 16383;
      for (var i2 = 0, len22 = len2 - extraBytes; i2 < len22; i2 += maxChunkLength) {
        parts.push(encodeChunk(uint8, i2, i2 + maxChunkLength > len22 ? len22 : i2 + maxChunkLength));
      }
      if (extraBytes === 1) {
        tmp = uint8[len2 - 1];
        parts.push(
          lookup[tmp >> 2] + lookup[tmp << 4 & 63] + "=="
        );
      } else if (extraBytes === 2) {
        tmp = (uint8[len2 - 2] << 8) + uint8[len2 - 1];
        parts.push(
          lookup[tmp >> 10] + lookup[tmp >> 4 & 63] + lookup[tmp << 2 & 63] + "="
        );
      }
      return parts.join("");
    }
  }
});

// wormhole-crypto/lib/concat-streams.js
function concatStreams(inputStreams) {
  let currentReader = null;
  const nextStream = (controller) => {
    const stream = inputStreams.shift();
    if (stream !== void 0) {
      currentReader = stream.getReader();
    } else {
      currentReader = null;
      controller.close();
    }
  };
  return new ReadableStream({
    start(controller) {
      nextStream(controller);
    },
    async pull(controller) {
      while (currentReader !== null) {
        const { value, done } = await currentReader.read();
        if (done) {
          nextStream(controller);
        } else {
          controller.enqueue(value);
          break;
        }
      }
    },
    async cancel(reason) {
      await Promise.all([
        currentReader && currentReader.cancel(reason),
        ...inputStreams.map((stream) => stream.cancel(reason))
      ]);
    }
  });
}

// wormhole-crypto/lib/transform-stream.js
function transformStream(sourceReadable, transformer) {
  let transformedReadable;
  let done;
  if (typeof TransformStream !== "undefined") {
    const transform = new TransformStream(transformer);
    done = sourceReadable.pipeTo(transform.writable);
    transformedReadable = transform.readable;
  } else {
    let resolveDone;
    let rejectDone;
    done = new Promise((resolve, reject) => {
      resolveDone = resolve;
      rejectDone = reject;
    });
    transformedReadable = new ReadableStream(new TransformStreamSource(sourceReadable, transformer, { resolveDone, rejectDone }));
  }
  done.catch(() => {
  });
  return {
    readable: transformedReadable,
    done
  };
}
var TransformStreamSource = class {
  constructor(readable, transformer = {}, { resolveDone, rejectDone }) {
    this.readable = readable;
    this.transformer = transformer;
    this.resolveDone = resolveDone;
    this.rejectDone = rejectDone;
    this.reader = readable.getReader();
    this.progressMade = false;
    this.wrappedController = null;
  }
  async start(controller) {
    this.wrappedController = {
      enqueue: (value) => {
        this.progressMade = true;
        controller.enqueue(value);
      },
      error: (reason) => {
        this.progressMade = true;
        if (!(reason instanceof Error)) {
          reason = new Error(`stream errored; reason: ${reason}`);
        }
        controller.error(reason);
        this.reader.cancel(reason).catch(() => {
        });
        this.rejectDone(reason);
      },
      terminate: () => {
        this.progressMade = true;
        controller.close();
        this.reader.cancel(new Error("stream terminated")).catch(() => {
        });
        this.resolveDone();
      }
    };
    if (this.transformer.start) {
      try {
        await this.transformer.start(this.wrappedController);
      } catch (err) {
        this.rejectDone(err);
        throw err;
      }
    }
  }
  async pull(controller) {
    this.progressMade = false;
    while (!this.progressMade) {
      try {
        const data = await this.reader.read();
        if (data.done) {
          if (this.transformer.flush) {
            await this.transformer.flush(this.wrappedController);
          }
          controller.close();
          this.resolveDone();
          return;
        }
        if (this.transformer.transform) {
          await this.transformer.transform(data.value, this.wrappedController);
        } else {
          this.wrappedController.enqueue(data.value);
        }
      } catch (err) {
        this.rejectDone(err);
        this.reader.cancel(err).catch(() => {
        });
        throw err;
      }
    }
  }
  async cancel(reason) {
    await this.reader.cancel(reason);
    if (reason instanceof Error) {
      this.rejectDone(reason);
    } else {
      this.rejectDone(new Error(`stream cancelled; reason: ${reason}`));
    }
  }
};

// wormhole-crypto/lib/extract-transformer.js
var ExtractTransformer = class {
  constructor(offset, length) {
    this.extractStart = offset;
    this.extractEnd = offset + length;
    this.offset = 0;
  }
  transform(chunk, controller) {
    const chunkStart = this.offset;
    const chunkEnd = this.offset + chunk.byteLength;
    this.offset = chunkEnd;
    const sliceStart = Math.max(this.extractStart - chunkStart, 0);
    const sliceEnd = Math.min(this.extractEnd - chunkStart, chunk.byteLength);
    if (sliceStart >= chunk.byteLength || sliceEnd <= 0) {
      return;
    }
    controller.enqueue(chunk.subarray(sliceStart, sliceEnd));
  }
  flush(controller) {
    if (this.offset < this.extractEnd) {
      controller.error(new Error("Stream passed through ExtractTransformer ended early"));
    }
  }
};

// wormhole-crypto/lib/slice-transformer.js
var SliceTransformer = class {
  constructor(firstChunkSize, restChunkSize) {
    this.chunkSize = firstChunkSize;
    this.restChunkSize = restChunkSize || firstChunkSize;
    this.partialChunk = new Uint8Array(this.chunkSize);
    this.offset = 0;
  }
  send(record, controller) {
    controller.enqueue(record);
    this.chunkSize = this.restChunkSize;
    this.partialChunk = new Uint8Array(this.chunkSize);
    this.offset = 0;
  }
  transform(chunk, controller) {
    let i = 0;
    if (this.offset > 0) {
      const len = Math.min(chunk.byteLength, this.chunkSize - this.offset);
      this.partialChunk.set(chunk.subarray(0, len), this.offset);
      this.offset += len;
      i += len;
      if (this.offset === this.chunkSize) {
        this.send(this.partialChunk, controller);
      }
    }
    while (i < chunk.byteLength) {
      const remainingBytes = chunk.byteLength - i;
      if (remainingBytes >= this.chunkSize) {
        const record = chunk.slice(i, i + this.chunkSize);
        i += this.chunkSize;
        this.send(record, controller);
      } else {
        const end = chunk.slice(i, i + remainingBytes);
        i += end.byteLength;
        this.partialChunk.set(end);
        this.offset = end.byteLength;
      }
    }
  }
  flush(controller) {
    if (this.offset > 0) {
      controller.enqueue(this.partialChunk.subarray(0, this.offset));
    }
  }
};

// wormhole-crypto/lib/ece.js
var MODE_ENCRYPT = "encrypt";
var MODE_DECRYPT = "decrypt";
var KEY_LENGTH = 16;
var TAG_LENGTH = 16;
var NONCE_LENGTH = 12;
var RECORD_SIZE = 64 * 1024;
var HEADER_LENGTH = KEY_LENGTH + 4 + 1;
var encoder = new TextEncoder();
function encryptedSize(plaintextSize2, rs = RECORD_SIZE) {
  if (!Number.isInteger(plaintextSize2)) {
    throw new TypeError("plaintextSize");
  }
  if (!Number.isInteger(rs)) {
    throw new TypeError("rs");
  }
  const chunkMetaLength = TAG_LENGTH + 1;
  return HEADER_LENGTH + plaintextSize2 + chunkMetaLength * Math.ceil(plaintextSize2 / (rs - chunkMetaLength));
}
function plaintextSize(encryptedSize2, rs = RECORD_SIZE) {
  if (!Number.isInteger(encryptedSize2)) {
    throw new TypeError("encryptedSize");
  }
  if (!Number.isInteger(rs)) {
    throw new TypeError("rs");
  }
  const chunkMetaLength = TAG_LENGTH + 1;
  const encryptedRecordsSize = encryptedSize2 - HEADER_LENGTH;
  return encryptedRecordsSize - chunkMetaLength * Math.ceil(encryptedRecordsSize / rs);
}
function encryptStream(input, secretKey, rs = RECORD_SIZE, salt = generateSalt(KEY_LENGTH)) {
  const stream = transformStream(
    input,
    new SliceTransformer(rs - TAG_LENGTH - 1)
  ).readable;
  return transformStream(
    stream,
    new ECETransformer(MODE_ENCRYPT, secretKey, rs, salt)
  ).readable;
}
function decryptStream(input, secretKey, rs = RECORD_SIZE) {
  const stream = transformStream(input, new SliceTransformer(HEADER_LENGTH, rs)).readable;
  return transformStream(
    stream,
    new ECETransformer(MODE_DECRYPT, secretKey, rs, null)
  ).readable;
}
function decryptStreamRange(secretKey, offset, length, totalEncryptedLength, rs = RECORD_SIZE) {
  if (!Number.isInteger(rs)) {
    throw new TypeError("rs");
  }
  const chunkMetaLength = TAG_LENGTH + 1;
  const startRecord = Math.floor(offset / (rs - chunkMetaLength));
  const offsetInStartRecord = offset % (rs - chunkMetaLength);
  const endRecord = Math.ceil((offset + length) / (rs - chunkMetaLength));
  const dataOffset = HEADER_LENGTH + startRecord * rs;
  let dataEnd = HEADER_LENGTH + endRecord * rs;
  const endsPrematurely = dataEnd < totalEncryptedLength;
  if (!endsPrematurely) {
    dataEnd = totalEncryptedLength;
  }
  return {
    ranges: [
      {
        offset: 0,
        length: HEADER_LENGTH
      },
      {
        offset: dataOffset,
        length: dataEnd - dataOffset
      }
    ],
    decrypt: (streams) => {
      if (!streams.every((stream) => stream instanceof ReadableStream)) {
        throw new TypeError("stream");
      }
      const encryptedStream = transformStream(concatStreams(streams), new SliceTransformer(HEADER_LENGTH, rs)).readable;
      const plaintextStream = transformStream(
        encryptedStream,
        new ECETransformer(MODE_DECRYPT, secretKey, rs, null, {
          startSeq: startRecord,
          endSeq: endRecord,
          endsPrematurely
        })
      ).readable;
      return transformStream(plaintextStream, new ExtractTransformer(offsetInStartRecord, length)).readable;
    }
  };
}
function checkSecretKey(secretKey) {
  if (secretKey.type !== "secret") {
    throw new Error('Invalid key: type must be "secret"');
  }
  if (secretKey.algorithm.name !== "HKDF") {
    throw new Error("Invalid key: algorithm must be HKDF");
  }
  if (!secretKey.usages.includes("deriveKey")) {
    throw new Error("Invalid key: usages must include deriveKey");
  }
  if (!secretKey.usages.includes("deriveBits")) {
    throw new Error("Invalid key: usages must include deriveBits");
  }
}
function generateSalt(len) {
  const salt = new Uint8Array(len);
  crypto.getRandomValues(salt);
  return salt;
}
var ECETransformer = class {
  constructor(mode, secretKey, rs, salt, seekOpts = {}) {
    if (mode !== MODE_ENCRYPT && mode !== MODE_DECRYPT) {
      throw new Error("mode must be either encrypt or decrypt");
    }
    checkSecretKey(secretKey);
    if (salt != null && salt.byteLength !== KEY_LENGTH) {
      throw new Error("Invalid salt length");
    }
    this.mode = mode;
    this.secretKey = secretKey;
    this.rs = rs;
    this.salt = salt;
    this.seekOpts = seekOpts;
    this.seq = -1;
    this.prevChunk = null;
    this.nonceBase = null;
    this.key = null;
  }
  async generateKey() {
    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: this.salt,
        info: encoder.encode("Content-Encoding: aes128gcm\0")
      },
      this.secretKey,
      {
        name: "AES-GCM",
        length: KEY_LENGTH * 8
      },
      false,
      ["encrypt", "decrypt"]
    );
  }
  async generateNonceBase() {
    const nonceBaseBuf = await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: this.salt,
        info: encoder.encode("Content-Encoding: nonce\0")
      },
      this.secretKey,
      NONCE_LENGTH * 8
    );
    return new Uint8Array(nonceBaseBuf);
  }
  generateNonce(seq) {
    if (seq > 4294967295) {
      throw new Error("record sequence number exceeds limit");
    }
    const nonce = this.nonceBase.slice();
    const dv = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
    const m = dv.getUint32(nonce.byteLength - 4);
    const xor = (m ^ seq) >>> 0;
    dv.setUint32(nonce.byteLength - 4, xor);
    return nonce;
  }
  pad(data, isLast) {
    const len = data.byteLength;
    if (len + TAG_LENGTH >= this.rs) {
      throw new Error("data too large for record size");
    }
    let padding;
    if (isLast) {
      padding = Uint8Array.of(2);
    } else {
      padding = new Uint8Array(this.rs - len - TAG_LENGTH);
      padding[0] = 1;
    }
    const result = new Uint8Array(data.byteLength + padding.byteLength);
    result.set(data, 0);
    result.set(padding, data.byteLength);
    return result;
  }
  unpad(data, isLast) {
    for (let i = data.byteLength - 1; i >= 0; i -= 1) {
      if (data[i] !== 0) {
        if (isLast) {
          if (data[i] !== 2) {
            throw new Error("delimiter of final record is not 2");
          }
        } else {
          if (data[i] !== 1) {
            throw new Error("delimiter of not final record is not 1");
          }
        }
        return data.slice(0, i);
      }
    }
    throw new Error("no delimiter found");
  }
  createHeader() {
    const header = new Uint8Array(HEADER_LENGTH);
    header.set(this.salt);
    const dv = new DataView(header.buffer, header.byteOffset, header.byteLength);
    dv.setUint32(KEY_LENGTH, this.rs);
    return header;
  }
  readHeader(buffer) {
    if (buffer.byteLength !== HEADER_LENGTH) {
      throw new Error("chunk is not expected header length");
    }
    const header = {};
    const dv = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    header.salt = buffer.slice(0, KEY_LENGTH);
    header.rs = dv.getUint32(KEY_LENGTH);
    const idlen = dv.getUint8(KEY_LENGTH + 4);
    if (idlen !== 0) {
      throw new Error("Implementation does not support non-zero idlen");
    }
    return header;
  }
  async encryptRecord(record, seq, isLast) {
    const nonce = this.generateNonce(seq);
    const paddedRecord = this.pad(record, isLast);
    const encryptedRecordBuf = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        tagLength: TAG_LENGTH * 8
      },
      this.key,
      paddedRecord
    );
    return new Uint8Array(encryptedRecordBuf);
  }
  async decryptRecord(encryptedRecord, seq, isLast) {
    const nonce = this.generateNonce(seq);
    const paddedRecordBuf = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        tagLength: TAG_LENGTH * 8
      },
      this.key,
      encryptedRecord
    );
    const paddedRecord = new Uint8Array(paddedRecordBuf);
    return this.unpad(paddedRecord, isLast);
  }
  async start(controller) {
    if (this.mode === MODE_ENCRYPT) {
      this.key = await this.generateKey();
      this.nonceBase = await this.generateNonceBase();
      controller.enqueue(this.createHeader());
      this.seq += 1;
    }
  }
  async transformPrevChunk(isLast, controller) {
    if (this.mode === MODE_ENCRYPT) {
      controller.enqueue(
        await this.encryptRecord(this.prevChunk, this.seq, isLast)
      );
    } else {
      if (this.seq === -1) {
        const header = this.readHeader(this.prevChunk);
        this.salt = header.salt;
        if (this.rs != null && this.rs !== header.rs) {
          throw new Error(
            "Record size declared in constructor does not match record size in encrypted stream"
          );
        }
        this.rs = header.rs;
        this.key = await this.generateKey();
        this.nonceBase = await this.generateNonceBase();
        const startSeq = this.seekOpts.startSeq;
        if (startSeq != null && startSeq > 0) {
          this.seq += startSeq;
        }
      } else {
        let expectEndPadding = false;
        if (isLast) {
          const endSeq = this.seekOpts.endSeq;
          if (endSeq != null && endSeq !== this.seq + 1) {
            throw new Error("Incorrect encrypted stream length");
          }
          expectEndPadding = !this.seekOpts.endsPrematurely;
        }
        controller.enqueue(
          await this.decryptRecord(this.prevChunk, this.seq, expectEndPadding)
        );
      }
    }
    this.seq += 1;
  }
  async transform(chunk, controller) {
    if (this.prevChunk) {
      await this.transformPrevChunk(false, controller);
    }
    this.prevChunk = chunk;
  }
  async flush(controller) {
    if (this.prevChunk) {
      await this.transformPrevChunk(true, controller);
    }
  }
};

// wormhole-crypto/lib/keychain.js
var import_base64_js = __toESM(require_base64_js(), 1);
var IV_LENGTH = 16;
var encoder2 = new TextEncoder();
function arrayToB64(array) {
  return import_base64_js.default.fromByteArray(array);
}
function arrayToB64Url(array) {
  return import_base64_js.default.fromByteArray(array).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
function b64ToArray(str) {
  return import_base64_js.default.toByteArray(str + "===".slice((str.length + 3) % 4));
}
function decodeBits(bitsB64) {
  let result;
  if (bitsB64 instanceof Uint8Array) {
    result = bitsB64;
  } else if (typeof bitsB64 === "string") {
    result = b64ToArray(bitsB64);
  } else if (bitsB64 == null) {
    result = crypto.getRandomValues(new Uint8Array(16));
  } else {
    throw new Error("Must be Uint8Array, string, or nullish");
  }
  if (result.byteLength !== 16) {
    throw new Error("Invalid byteLength: must be 16 bytes");
  }
  return result;
}
var Keychain = class {
  constructor(key, salt) {
    this.key = decodeBits(key);
    this.salt = decodeBits(salt);
    this.mainKeyPromise = crypto.subtle.importKey(
      "raw",
      this.key,
      "HKDF",
      false,
      ["deriveBits", "deriveKey"]
    );
    this.metaKeyPromise = this.mainKeyPromise.then(
      (mainKey) => crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: this.salt,
          info: encoder2.encode("metadata")
        },
        mainKey,
        {
          name: "AES-GCM",
          length: 128
        },
        false,
        ["encrypt", "decrypt"]
      )
    );
    this.authTokenPromise = this.mainKeyPromise.then(
      (mainKey) => crypto.subtle.deriveBits(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: this.salt,
          info: encoder2.encode("authentication")
        },
        mainKey,
        128
      )
    ).then((authTokenBuf) => new Uint8Array(authTokenBuf));
  }
  get keyB64() {
    return arrayToB64Url(this.key);
  }
  get saltB64() {
    return arrayToB64(this.salt);
  }
  async authToken() {
    return await this.authTokenPromise;
  }
  async authTokenB64() {
    const authToken = await this.authToken();
    return arrayToB64(authToken);
  }
  async authHeader() {
    const authTokenB64 = await this.authTokenB64();
    return `Bearer sync-v1 ${authTokenB64}`;
  }
  setAuthToken(authToken) {
    this.authTokenPromise = Promise.resolve(decodeBits(authToken));
  }
  async encryptStream(stream) {
    if (!(stream instanceof ReadableStream)) {
      throw new TypeError("stream");
    }
    const mainKey = await this.mainKeyPromise;
    return encryptStream(stream, mainKey);
  }
  async decryptStream(encryptedStream) {
    if (!(encryptedStream instanceof ReadableStream)) {
      throw new TypeError("encryptedStream");
    }
    const mainKey = await this.mainKeyPromise;
    return decryptStream(encryptedStream, mainKey);
  }
  async decryptStreamRange(offset, length, totalEncryptedLength) {
    if (!Number.isInteger(offset)) {
      throw new TypeError("offset");
    }
    if (!Number.isInteger(length)) {
      throw new TypeError("length");
    }
    if (!Number.isInteger(totalEncryptedLength)) {
      throw new TypeError("totalEncryptedLength");
    }
    const mainKey = await this.mainKeyPromise;
    return decryptStreamRange(mainKey, offset, length, totalEncryptedLength);
  }
  async encryptMeta(meta) {
    if (!(meta instanceof Uint8Array)) {
      throw new TypeError("meta");
    }
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const metaKey = await this.metaKeyPromise;
    const encryptedMetaBuf = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: 128
      },
      metaKey,
      meta
    );
    const encryptedMeta = new Uint8Array(encryptedMetaBuf);
    const ivEncryptedMeta = new Uint8Array(IV_LENGTH + encryptedMeta.byteLength);
    ivEncryptedMeta.set(iv, 0);
    ivEncryptedMeta.set(encryptedMeta, IV_LENGTH);
    return ivEncryptedMeta;
  }
  async decryptMeta(ivEncryptedMeta) {
    if (!(ivEncryptedMeta instanceof Uint8Array)) {
      throw new Error("ivEncryptedMeta");
    }
    const iv = ivEncryptedMeta.slice(0, IV_LENGTH);
    const encryptedMeta = ivEncryptedMeta.slice(IV_LENGTH);
    const metaKey = await this.metaKeyPromise;
    const metaBuf = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: 128
      },
      metaKey,
      encryptedMeta
    );
    const meta = new Uint8Array(metaBuf);
    return meta;
  }
};
export {
  Keychain,
  encryptedSize,
  plaintextSize
};
