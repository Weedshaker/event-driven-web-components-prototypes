// small shim to simulate nodejs package base64 at keychain.js "import base64 from 'base64-js'"
function fromByteArray(uint8) {
  let binary = ''
  for (let i = 0; i < uint8.length; i++) {
    binary += String.fromCharCode(uint8[i])
  }
  return btoa(binary)
}

function toByteArray(base64) {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

export default {
  fromByteArray,
  toByteArray
}