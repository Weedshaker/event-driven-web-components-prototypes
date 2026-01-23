/* global self */
/* global location */

const currentScriptUrl = new URL(document.currentScript.src)

// @ts-ignore
self.Environment = {
  isTestingEnv: location.hostname === 'localhost',
  language: currentScriptUrl.searchParams.get('language') || document.documentElement.getAttribute('lang') || 'en',
  stage: currentScriptUrl.searchParams.get('stage') || document.documentElement.getAttribute('stage') || 'alpha',
  version: currentScriptUrl.searchParams.get('version') || document.documentElement.getAttribute('version') || '6.1.0', // https://semver.org/
  /**
   * Get custom mobile breakpoint
   * @param {{constructor?: string, tagName?: string, namespace?: string}} organism
   * @return {string}
   */
  mobileBreakpoint: ({ constructor, tagName, namespace } = {}) => {
    switch (true) {
      default:
        return '767px'
    }
  }
}

/**
 * XSS Content Security Policy
 * 
 * https://content-security-policy.com/examples/meta/
 * is enforced by: <meta http-equiv="Content-Security-Policy" content="require-trusted-types-for 'script'">
 * 
 * Sink uses trusted type only: https://web.dev/articles/trusted-type
 * Avoid XSS attacks by sanitizing the html according to: https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/XSS
 * and the target list: https://github.com/cure53/DOMPurify/blob/27e8496bcd689a16acc7d0bf7c88b933efad569a/demos/hooks-mentaljs-demo.html#L20
 * plus: https://stackoverflow.com/questions/6976053/xss-which-html-tags-and-attributes-can-trigger-javascript-events
 * stackoverflow citation and conclusion: "I didn't knew about those new attributes. I checked, and it seems that the only attributes that start with on are all Javascript event triggers. I will probably just remove all that match that pattern."
 * NOTE: script tags are already automatically escaped by modern browsers, so we only target <image, <img starting tags and "javascript:"
 *
 * @static
 * @param {string} html
 * @return {string}
 */
if (typeof self.trustedTypes?.createPolicy === 'function' && document.querySelector('meta[http-equiv=Content-Security-Policy][content*=require-trusted-types-for]')) {
  self.trustedTypes.createPolicy('default', {
    // first sanitize tags eg.: <img src="xyz" onload=alert('XSS')>, <img src="xyz" onmouseover=alert('XSS')>, <image/src/onerror=alert('XSS')>, etc.
    // second sanitize tags eg.: <a href="javascript:alert(document.location);">XSS</a>, <form action="javascript:alert(document.location);"><input type="submit" /></form>, etc.
    createHTML: string => string.replace(/<[a-z]+[\s|\/][^>]*[\s|\/]on[a-z]{4,10}=[^>]*>/gi, '').replace(/<[a-z]+[\s|\/][^>]*javascript:[^>]*>/gi, ''),
    createScriptURL: string => string, // unsafe but including webworker's, service workers, etc. is okay
    createScript: string => string // unsafe but eval at css templates is okay
  })
}
