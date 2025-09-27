const base64ToBytes = {
  
  /**
   * Encode an Uint8Array to Base64.
   * 
   * @param   {Uint8Array} bytes - An array of unsigned 8-bit numbers to be Base64 encoded.
   * @returns {string}     A Base64 string.
   */
  encode(bytes) {

    return btoa(String.fromCharCode(...bytes))

  },


  /**
   * Converts a Base64 string into a Uint8Array.
   * 
   * @param   {string}                  base64String - A Base64 string.
   * @returns {Uint8Array<ArrayBuffer>} An Uint8Array.
   */
  decode(base64String) {

    const binary = atob(base64String)
    const len = binary.length

    const bytes = new Uint8Array(len)

    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i)
    }

    return bytes

  }

}



export default base64ToBytes