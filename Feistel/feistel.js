/**
 * This function implements a Feistel Cipher with 4 rounds, where the block size is 16 bits and the key size is 16 bits.
 * The Feistel function uses the following S-box: 
 * 0 1 2 3 4 5 6 7 8 9 A B C D E F 
 * 6 7 8 9 A B C D E F 0 1 2 3 4 5 
 * The key is divided into 2 8-bit subkeys, K1 and K2, where K1 is the leftmost 8 bits and K2 is the rightmost 8 bits, alternating every round.
 * The Feistel cipher with 4 rounds can be described as follows:
 * 1. Divide the 16-bit plaintext block P into two 8-bit halves, L0 and R0.
 * 2. For i = 1 to 4, do the following:
 *    - Calculate Li = Ri-1.
 *    - Calculate Ri = Li-1 ^ F(Ri-1, Ki), where F is a round function that takes Ri-1 as input and produces a 8-bit output, and Ki is the ith subkey.
 *    - The round function XORs the Ri-1 and Ki then substitutes the 8-bits using the S-Box.
 *    - Example:
 *      - Ri-1 = 10101100
 *      - Ki = 10101010
 *      - XORed = 00000110
 *      - Substituted using S-Box 0000->0110, 0110->1100, thus 01101100
 * 
 * @param {string} plaintext - The plaintext to be encrypted or decrypted. Must be a 16-bit binary string.
 * @param {string} key - The key to be used for encryption or decryption. Must be a 16-bit binary string.
 * @param {string} mode - The mode of operation. Must be either "encrypt" or "decrypt".
 * @returns {string} - The encrypted or decrypted result as a 16-bit binary string.
 */
function feistelCipher(plaintext, key, mode) {
  try {
    // Check if plaintext and key are 16-bit binary strings
    if (!/^[01]{16}$/.test(plaintext) || !/^[01]{16}$/.test(key)) {
      throw new Error("Plaintext and key must be 16-bit binary strings");
    }

    // Divide plaintext into two 8-bit halves
    let L0 = plaintext.slice(0, 8);
    let R0 = plaintext.slice(8);

    // Divide key into two 8-bit subkeys
    let K1 = key.slice(0, 8);
    let K2 = key.slice(8);

    // Define the S-Box
    let sBox = {
      "0000": "0110",
      "0001": "0001",
      "0010": "1010",
      "0011": "1011",
      "0100": "1000",
      "0101": "1100",
      "0110": "1101",
      "0111": "0000",
      "1000": "0010",
      "1001": "1110",
      "1010": "1111",
      "1011": "1001",
      "1100": "0100",
      "1101": "0011",
      "1110": "0111",
      "1111": "0101"
    };

    // Define the round function
    function roundFunction(Ri_1, Ki) {
      // XOR Ri-1 and Ki
      let XORed = "";
      for (let i = 0; i < 8; i++) {
        XORed += (Ri_1[i] ^ Ki[i]);
      }

      // Substitute using S-Box
      let substituted = "";
      for (let i = 0; i < 8; i += 4) {
        substituted += sBox[XORed.slice(i, i+4)];
      }

      return substituted;
    }

    // Perform encryption or decryption
    let L, R;
    if (mode === "encrypt") {
      L = L0;
      R = R0;
      for (let i = 1; i <= 4; i++) {
        let Li = R;
        let Ri = "";
        if (i % 2 === 1) {
          Ri = L ^ roundFunction(R, K1);
        } else {
          Ri = L ^ roundFunction(R, K2);
        }
        L = Li;
        R = Ri;
      }
    } else if (mode === "decrypt") {
      L = R0;
      R = L0;
      for (let i = 4; i >= 1; i--) {
        let Li = R;
        let Ri = "";
        if (i % 2 === 1) {
          Ri = L ^ roundFunction(R, K2);
        } else {
          Ri = L ^ roundFunction(R, K1);
        }
        L = Li;
        R = Ri;
      }
    } else {
      throw new Error("Mode must be either 'encrypt' or 'decrypt'");
    }

    // Combine L and R to get the result
    let result = L + R;
    return result;
  } catch (error) {
    // Log the error
    console.error(error);
    return "0000000000000000";
  }
}