// @ts-check

/* global ResizeObserver */

import { Shadow } from './Shadow.js'

/**
 * ResizeObserver is a helper which sets up a new ResizeObserver in the context of a web component
 *
 * @export
 * @function ResizeObserver
 * @param {Function | *} ChosenClass
 * @attribute {'string'} [resizeObserverInit=`{
      'box': undefined
    }`]
 * @requires {
      Shadow: {
        connectedCallback,
        disconnectedCallback,
        parseAttribute,
        root,
        shadowRoot
      }
    }
 * @property {
      resizeObserver,
      resizeObserverInit,
      resizeCallback,
      resizeObserveStart,
      resizeObserveStop
    }
 * @return {CustomElementConstructor | *}
 */
export const Resize = (ChosenClass = Shadow()) => class Resize extends ChosenClass {
  /**
   * Creates an instance of ResizeObserver. The constructor will be called for every custom element using this class when initially created.
   *
   * @param {{resizeObserverInit: ResizeObserverOptions | undefined}} [options = {resizeObserverInit: undefined}]
   * @param {*} args
   */
  constructor (options = { resizeObserverInit: undefined }, ...args) {
    super(options, ...args)

    /**
     * Digest attribute to have ResizeObservers or not
     * this will trigger this.resizeCallback and can be extended
     * see => https://developer.mozilla.org/en-US/docs/Web/API/ResizeObserverOptions Properties
     *
     * @type {ResizeObserverOptions}
     */
    this.resizeObserverInit = typeof options.resizeObserverInit === 'object' ? options.resizeObserverInit : Resize.parseAttribute(this.getAttribute('resizeObserverInit'))
    /** @type {ResizeObserver} */
    this.resizeObserver = new ResizeObserver(this.resizeCallback.bind(this))
    // add default ResizeObserverOptions Props
    this.resizeObserverInit = Object.assign({
      box: undefined
    }, this.resizeObserverInit)
    /** @return {void} */
    this.resizeObserveStart = (target = this) => {
      // @ts-ignore
      this.resizeObserver.observe(target, this.resizeObserverInit)
    }
    /** @return {void} */
    this.resizeObserveStop = () => this.resizeObserver.disconnect()
  }

  /**
   * Lifecycle callback, triggered when node is attached to the dom
   *
   * @return {void}
   */
  connectedCallback () {
    super.connectedCallback()
    this.resizeObserveStart()
  }

  /**
   * Lifecycle callback, triggered when node is detached from the dom
   *
   * @return {void}
   */
  disconnectedCallback () {
    super.disconnectedCallback()
    this.resizeObserveStop()
  }

  /**
   * observes resizes on this + children changes
   *
   * @param {ResizeObserverEntry} entries
   * @param {ResizeObserver} observer
   * @return {void}
   */
  resizeCallback (entries, observer) {}
}
