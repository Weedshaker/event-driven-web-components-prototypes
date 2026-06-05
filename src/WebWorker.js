// @ts-check

/* global Blob */
/* global BlobBuilder */
/* global HTMLElement */
/* global self */
/* global Worker */

/**
 * WebWorker is a helper which executes simple functions inside a webworker (spans one worker per function)
 *
 * @export
 * @function WebWorker
 * @param {CustomElementConstructor} ChosenHTMLElement
 * @property {
      webWorker,
      getWebWorkerPromise,
      webWorkerMap,
      self._webWorkerMap
    }
 * @return {CustomElementConstructor | *}
 */
export const WebWorker = (ChosenHTMLElement = HTMLElement) => class WebWorker extends ChosenHTMLElement {
  /**
   * Convert function to web worker and receive a promise returning the results
   * more Infos at: https://github.com/Weedshaker/ProxifyJS/blob/master/JavaScript/Classes/Helper/Misc/WebWorkers.js
   *
   * @param {function|string} func
   * @param {any[]} args
   * @return {Promise<any>}
   */
  webWorker (func, ...args) {
    const key = func = typeof func === 'string' ? func : func.toLocaleString()
    const isModule = func.includes('//import ')
    if (this.webWorkerMap.has(key)) {
      // @ts-ignore
      const { worker, promise } = this.webWorkerMap.get(key)
      const newPromise = WebWorker.getWebWorkerPromise(worker, args, promise, isModule)
      this.webWorkerMap.set(key, { worker, promise: newPromise })
      return newPromise
    }
    let importString = ''
    if (isModule) {
      const matches = []
      func = func.replace(/\/\/import\s[^\n]*/g, match => {
        matches.push(match.replace('//', ''))
        return ''
      })
      importString = matches.join('\n')
    }
    func = func.replace(/this\./g, '')
    func = func.replace(new RegExp(`${this.constructor.name}\\.`, 'g'), '')
    func = /^.*?=>.*?/.test(func) ? `(${func})` : !/^function/.test(func) ? `function ${func}` : func
    func = func.replace(/(function\s)async\s(.*)/s, 'await async $1$2') // fix async function
    func = func.replace(/function\s#/, 'function ') // fix private functions
    func = func.replace(/function\sfunction\s/, 'function ') // ios 16 bug which made await async function function ...
    let response = `${importString}\n onmessage=async (event)=>{
      const result = ${func}(...event.data)
      postMessage(result, {transfer: ${isModule ? 'getAllReadableStreams(result)' : '[]'}})}${isModule ? `;function ${WebWorker.getAllReadableStreams.toLocaleString().replace(/WebWorker\./g, '')}` : ''}`
    // bypass trusted type sinks
    if (document.querySelector('meta[http-equiv=Content-Security-Policy][content*=require-trusted-types-for]') && response.includes('eval')) response += ';if (typeof self.trustedTypes?.createPolicy === \'function\') self.trustedTypes.createPolicy(\'default\', {createScript: string => string})'
    let blob
    try {
      blob = new Blob([response], { type: 'application/javascript' })
    } catch (e) { // Backwards-compatibility
      // @ts-ignore
      self.BlobBuilder = self.BlobBuilder || self.WebKitBlobBuilder || self.MozBlobBuilder
      // @ts-ignore
      blob = new BlobBuilder()
      blob.append(response)
      blob = blob.getBlob()
    }
    const worker = new Worker(URL.createObjectURL(blob), isModule
      ? { type: 'module' }
      : {}
    )
    const promise = WebWorker.getWebWorkerPromise(worker, args, undefined, isModule)
    this.webWorkerMap.set(key, { worker, promise })
    return promise
  }

  /**
   * @static
   * @param {Worker} worker
   * @param {any[]} args
   * @param {Promise<any>|null} [promise=null]
   * @param {boolean} [isModule=false]
   * @return {Promise<any>}
   */
  static getWebWorkerPromise (worker, args, promise = null, isModule = false) {
    return new Promise((resolve, reject) => {
      const triggerWorker = () => {
        worker.onmessage = (e) => resolve(e.data)
        worker.onerror = (e) => reject(e)
        worker.postMessage(args, {transfer: isModule ? WebWorker.getAllReadableStreams(args) : []}) // can only have one argument as message
      }
      promise ? promise.finally(() => triggerWorker()) : triggerWorker()
    })
  }

  static getAllReadableStreams (objs, props = ['text']) {
    const streams = []
    if (objs instanceof ReadableStream) {
      streams.push(objs)
    } else if (Array.isArray(objs)) {
      streams.push(...objs.flatMap(obj => WebWorker.getAllReadableStreams(obj, props)))
    } else if (objs && typeof objs === 'object') {
      streams.push(...Object.keys(objs).flatMap(key => props.includes(key) ? WebWorker.getAllReadableStreams(objs[key], props) : []))
    }
    return streams
  }

  /**
   * @return {Map<string, {worker: Worker, promise: Promise<any>}>}
   */
  get webWorkerMap () {
    // @ts-ignore
    return self._webWorkerMap || (self._webWorkerMap = new Map())
  }
}
