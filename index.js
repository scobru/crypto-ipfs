/**
 * @fileoverview This file contains the MecenateHelper class.
 * @module mecenate-helper
 * @requires fernet
 * @requires tweetnacl
 * @requires pbkdf2
 * @requires get-random-values
 * @requires multihashes
 * @requires ipfs-only-hash
 * @requires ethers
 * @requires asymmetric-crypto
 * @requires crypto-js
 */

const fernet = require("fernet");
const tweetnacl = require("tweetnacl");
const pbkdf2 = require("pbkdf2");
const getRandomValues = require("get-random-values");
const multihash = require("multihashes");
const sha256_cid = require("ipfs-only-hash");
const ethers = require("ethers");
const crypto = require("asymmetric-crypto");
const CryptoJS = require("crypto-js");

/**
 * Constants used in the MecenateHelper class.
 *
 * @constant {number} MAX_UINT32 - The maximum value of a 32-bit unsigned integer.
 * @constant {number} MAX_UINT8 - The maximum value of an 8-bit unsigned integer.
 * @constant {number} FERNET_SECRET_LENGTH - The length of a Fernet secret.
 * @constant {number} NONCE_LENGTH - The length of a nonce.
 */
const MAX_UINT32 = Math.pow(2, 32) - 1;
const MAX_UINT8 = Math.pow(2, 8) - 1;
const FERNET_SECRET_LENGTH = 32;
const NONCE_LENGTH = 24;

/**
 * Generates a random number based on the environment.
 * @returns {number} A random number between 0 and 1.
 */
const randomNumber = () => {
  if (typeof window === "undefined") {
    return getRandomValues(new Uint8Array(1))[0] / MAX_UINT8;
  }
  return getRandomValues(new Uint32Array(1))[0] / MAX_UINT32;
};

/**
 * Generates a random string of a specified length.
 * @returns {string} A random alphanumeric string.
 */
const randomString = () => {
  let result = "";
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const charactersLength = characters.length;
  for (let i = 0; i < FERNET_SECRET_LENGTH; i++) {
    result += characters.charAt(Math.floor(randomNumber() * charactersLength));
  }
  return result;
};

/**
 * Converts a given input to a multihash buffer object.
 * @param {string|Buffer} input - The input data to be converted.
 * @param {string} inputType - The type of the input ('raw', 'sha2-256', 'hex', or 'b58').
 * @returns {Buffer} The multihash buffer object.
 */
async function multihashFrom(input, inputType) {
  const inputTypes = ["raw", "sha2-256", "hex", "b58"];
  let contentid;
  if (inputType === "raw") {
    contentid = multihash.fromB58String(
      await sha256_cid.of(Buffer.from(input))
    );
  } else if (inputType === "sha2-256") {
    input = input.slice(0, 2) === "0x" ? input.slice(2) : input;
    contentid = multihash.fromHexString("1220" + input);
  } else if (inputType === "hex") {
    input = input.slice(0, 2) === "0x" ? input.slice(2) : input;
    contentid = multihash.fromHexString(input);
  } else if (inputType === "b58") {
    contentid = multihash.fromB58String(input);
  } else {
    throw new Error(
      `Invalid inputType: ${inputType} should be one of [${inputTypes}]`
    );
  }

  multihash.validate(contentid);

  return contentid;
}

/**
 * Converts a multihash buffer object to a specified output type.
 * @param {Buffer} contentid - The multihash buffer object.
 * @param {string} outputType - The desired output type ('prefix', 'digest', 'hex', or 'b58').
 * @returns {string} The multihash in the specified output format.
 */
async function multihashTo(contentid, outputType) {
  const outputTypes = ["prefix", "digest", "hex", "b58"];
  if (outputType === "prefix") {
    return "0x" + multihash.prefix(contentid).toString("hex");
  } else if (outputType === "digest") {
    return "0x" + multihash.toHexString(multihash.decode(contentid).digest);
  } else if (outputType === "hex") {
    return "0x" + multihash.toHexString(contentid);
  } else if (outputType === "b58") {
    return multihash.toB58String(contentid);
  } else {
    throw new Error(
      `Invalid outputType: ${outputType} should be one of [${outputTypes}]`
    );
  }
}

/**
 * The MecenateHelper class.
 * @class
 * @classdesc The MecenateHelper class contains helper functions for the Mecenate protocol.
 * @hideconstructor
 */
const MecenateHelper = {
  randomNumber: randomNumber,
  randomString: randomString,
  /**
   * Generates a random string of a specified length.
   * @returns {string} A random alphanumeric string.
   */
  multihash: async ({ input, inputType, outputType }) =>
    multihashTo(await multihashFrom(input, inputType), outputType),

  /**
   * Constants used in the Mecenate Protocol.
   * @enum {number} TOKEN_TYPES - The types of tokens used in the Mecenate Protocol.
   * @enum {number} TOKEN_TYPES.NAN - The type of token used for ETH tokens.
   * @enum {number} TOKEN_TYPES.MUSE - The type of token used for MUSE tokens.
   * @enum {number} TOKEN_TYPES.DAI - The type of token used for DAI tokens.
   */
  constants: {
    TOKEN_TYPES: {
      NaN: 0,
      MUSE: 1,
      DAI: 2,
    },
  },

  /**
   * Encodes the create call for a contract using its ABI and provided values.
   * @param {Array} templateABI - The ABI array of the contract.
   * @param {Array} abiValues - The values for the ABI.
   * @returns {string} The encoded calldata.
   */
  encodeCreateCall: (templateABI, abiValues) => {
    const abi = new ethers.utils.Interface(templateABI);
    const calldata = abi.functions.initialize.encode(abiValues);
    return calldata;
  },

  crypto: {
    /**
     * Symmetric encryption utilities using the Fernet encryption algorithm.
     */
    symmetric: {
      /**
       * Generates a random symmetric key using Fernet encryption.
       * @returns {string} A random symmetric key, Base64-encoded.
       */
      generateKey: () => {
        let key = Buffer.from(randomString()).toString("base64");
        let secret = fernet.decode64toHex(key);
        while (secret.length !== fernet.hexBits(256)) {
          key = Buffer.from(randomString()).toString("base64");
          secret = fernet.decode64toHex(key);
        }
        return key;
      },

      /**
       * Encrypts a message using a secret key with Fernet encryption.
       * @param {string} secretKey - The secret key to encrypt the message with, Base64-encoded.
       * @param {string} msg - The message to be encrypted.
       * @returns {string} The encrypted message, as a Fernet token.
       */
      encryptMessage: (secretKey, msg) => {
        const secret = new fernet.Secret(secretKey);
        const token = new fernet.Token({ secret, ttl: 0 });
        return token.encode(msg);
      },

      /**
       * Decrypts a message using a secret key with Fernet encryption.
       * @param {string} secretKey - The secret key to decrypt the message with, Base64-encoded.
       * @param {string} encryptedMessage - The encrypted message to be decrypted, as a Fernet token.
       * @returns {string} The decrypted message.
       */
      decryptMessage: (secretKey, encryptedMessage) => {
        const secret = new fernet.Secret(secretKey);
        const token = new fernet.Token({
          secret,
          ttl: 0,
          token: encryptedMessage,
        });
        return token.decode();
      },
    },
    asymmetric: {
      /**
       * Generates a key pair from a signature and salt using PBKDF2 and TweetNaCl's box module.
       * @param {(string|Buffer|TypedArray|DataView)} sig - The signature to be used to generate the key pair.
       * @param {(TypedArray|string|number)} salt - The salt to be used in PBKDF2.
       * @returns {Object} Key pair object containing 'publicKey' and 'secretKey' properties.
       */
      generateKeyPair: (sig, salt) =>
        tweetnacl.box.keyPair.fromSecretKey(
          pbkdf2.pbkdf2Sync(sig, salt, 1000, 32)
        ),

      /**
       * Generate a key pair from seed
       * @param {Uint8Array} seed
       * @returns {Object} Key pair object containing 'publicKey' and 'secretKey' properties.
       */

      generateKeyPairFromSeed: (seed) => tweetnacl.sign.keyPair.fromSeed(seed),
      /**
       * Generates a nonce using TweetNaCl's randomBytes function.
       * @returns {Uint8Array} A random nonce.
       */
      generateNonce: () => tweetnacl.randomBytes(NONCE_LENGTH),

      /**
       * Encrypts a message using a nonce, public key, and secret key with TweetNaCl's box module.
       * @param {string} msg - The message to be encrypted.
       * @param {Uint8Array} nonce - The nonce to be used for encryption.
       * @param {Uint8Array} publicKey - The public key of the receiver.
       * @param {Uint8Array} secretKey - The secret key of the sender.
       * @returns {Uint8Array} The encrypted message.
       */
      encryptMessage: (msg, nonce, publicKey, secretKey) => {
        const encoder = new TextEncoder();
        const encodedMessage = encoder.encode(msg);
        return tweetnacl.box(encodedMessage, nonce, publicKey, secretKey);
      },

      /**
       * Decrypts a message using a nonce, public key, and secret key with TweetNaCl's box module.
       * @param {Uint8Array} box - The encrypted message.
       * @param {Uint8Array} nonce - The nonce to be used for decryption.
       * @param {Uint8Array} publicKey - The public key of the sender.
       * @param {Uint8Array} secretKey - The secret key of the receiver.
       * @returns {string} The decrypted message.
       */

      decryptMessage: (box, nonce, publicKey, secretKey) => {
        const decoder = new TextDecoder();
        const encodedMessage = tweetnacl.box.open(
          box,
          nonce,
          publicKey,
          secretKey
        );
        if (!encodedMessage) {
          throw new Error(
            "Asymmetric decryption failed. Make sure the public key belongs to the sender and the private key belongs to the receiver"
          );
        }
        return decoder.decode(encodedMessage);
      },
      secretBox: {
        /**
         * Encrypts a message using a nonce and a secret key with TweetNaCl's secretbox module.
         * @param {string} msg - The message to be encrypted.
         * @param {Uint8Array} nonce - The nonce to be used for encryption.
         * @param {Uint8Array} secretKey - The secret key.
         * @returns {Uint8Array} The encrypted message.
         */
        encryptMessage: (msg, nonce, secretKey) => {
          const encoder = new TextEncoder();
          const encodedMessage = encoder.encode(msg);
          return tweetnacl.secretbox(encodedMessage, nonce, secretKey);
        },

        /**
         * Decrypts a message using a nonce and a secret key with TweetNaCl's secretbox module.
         * @param {Uint8Array} box - The encrypted message.
         * @param {Uint8Array} nonce - The nonce to be used for decryption.
         * @param {Uint8Array} secretKey - The secret key.
         * @returns {string|null} The decrypted message, or null if decryption failed.
         */
        decryptMessage: (box, nonce, secretKey) => {
          const decoder = new TextDecoder();
          const encodedMessage = tweetnacl.secretbox.open(
            box,
            nonce,
            secretKey
          );
          if (encodedMessage === null) {
            throw new Error(
              "The message cannot be decrypted, the key is incorrect or the message is corrupted"
            );
          }
          return decoder.decode(encodedMessage);
        },
      },
      /**
       * Generates a key pair.
       * @returns {Object} An object containing a 'publicKey' and 'secretKey'.
       */
      keyPair: () => {
        const keyPair = crypto.keyPair();
        return keyPair;
      },

      /**
       * Generates a key pair from a secret key.
       * @param {string} secretKey - The secret key to generate the key pair from.
       * @returns {Object} An object containing a 'publicKey' and 'secretKey'.
       */
      fromSecretKey: (secretKey) => {
        return crypto.fromSecretKey(secretKey);
      },

      /**
       * Encrypts a message using a public key and a secret key only, nonce returned.
       * @param {string} data - The message to be encrypted.
       * @param {string} theirPublicKey - The public key of the receiver.
       * @param {string} mySecretKey - The secret key of the sender.
       * @returns {Object} An object containing 'data' (encrypted data) and 'nonce'.
       */
      encrypt: (data, theirPublicKey, mySecretKey) => {
        return crypto.encrypt(data, theirPublicKey, mySecretKey);
      },

      /**
       * Decrypts a message using a public key, a secret key, and a nonce.
       * @param {string} data - The message to be decrypted.
       * @param {string} nonce - The nonce used in the encryption process.
       * @param {string} theirPublicKey - The public key of the sender.
       * @param {string} mySecretKey - The secret key of the receiver.
       * @returns {string} The decrypted message.
       */
      decrypt: (data, nonce, theirPublicKey, mySecretKey) => {
        return crypto.decrypt(data, nonce, theirPublicKey, mySecretKey);
      },

      /**
       * Signs a message using a secret key.
       * @param {string} data - The message to be signed.
       * @param {string} secretKey - The secret key of the sender.
       * @returns {string} The signature of the message.
       */
      sign: (data, secretKey) => {
        return crypto.sign(data, secretKey);
      },

      /**
       * Verifies a message using a public key.
       * @param {string} data - The message to be verified.
       * @param {string} signature - The signature of the message.
       * @param {string} publicKey - The public key of the sender.
       * @returns {boolean} True if the message is verified, false otherwise.
       */
      verify: (data, signature, publicKey) => {
        return crypto.verify(data, signature, publicKey);
      },
    },
    aes: {
      /**
       * Encrypts a message using a secret key.
       * @param {string} plaintext - The message to be encrypted.
       * @param {string} secretKey - The secret key to encrypt the message with.
       * @returns {Object} The encrypted message, along with the salt and iv used during encryption. Each of these three properties is a Base64-encoded string.
       * @property {string} salt - The random salt used during encryption, Base64-encoded.
       * @property {string} iv - The random initialization vector (iv) used during encryption, Base64-encoded.
       * @property {string} ciphertext - The encrypted message, Base64-encoded.
       */
      encryptText: (plaintext, secretKey) => {
        const salt = CryptoJS.lib.WordArray.random(128 / 8);
        const key = CryptoJS.PBKDF2(secretKey, salt, { keySize: 256 / 32 });
        const iv = CryptoJS.lib.WordArray.random(128 / 8);
        const ciphertext = CryptoJS.AES.encrypt(plaintext, key, { iv: iv });
        const saltString = CryptoJS.enc.Base64.stringify(salt);
        const ivString = CryptoJS.enc.Base64.stringify(iv);
        const ciphertextString = ciphertext.toString();
        return {
          salt: saltString,
          iv: ivString,
          ciphertext: ciphertextString,
        };
      },

      /**
       * Decrypts a message using a secret key, a stored salt, a stored IV, and a password.
       * @param {string} storedSaltString - The stored salt string, Base64-encoded.
       * @param {string} storedIvString - The stored initialization vector (iv) string, Base64-encoded.
       * @param {string} storedCiphertextString - The stored ciphertext string, Base64-encoded.
       * @param {string} password - The password used for decryption.
       * @returns {string} The decrypted plaintext message.
       */
      decryptText: (
        storedSaltString,
        storedIvString,
        storedCiphertextString,
        password
      ) => {
        const storedSalt = CryptoJS.enc.Base64.parse(storedSaltString);
        const storedIv = CryptoJS.enc.Base64.parse(storedIvString);
        const storedKey = CryptoJS.PBKDF2(password, storedSalt, {
          keySize: 256 / 32,
        });
        const decrypted = CryptoJS.AES.decrypt(
          storedCiphertextString,
          storedKey,
          { iv: storedIv }
        );
        const decryptedPlaintext = decrypted.toString(CryptoJS.enc.Utf8);
        console.log("Decrypted plaintext:", decryptedPlaintext);

        return decryptedPlaintext;
      },

      /**
       * Encrypts an object using a secret key.
       * @param {Object} data - The object to be encrypted.
       * @param {string} secretKey - The secret key to encrypt the object with.
       * @returns {Object} The encrypted object, along with the salt and iv used during encryption. Each of these three properties is a Base64-encoded string.
       * @property {string} salt - The random salt used during encryption, Base64-encoded.
       * @property {string} iv - The random initialization vector (iv) used during encryption, Base64-encoded.
       * @property {string} ciphertext - The encrypted object, Base64-encoded.
       */
      encryptObject: (data, secretKey) => {
        const salt = CryptoJS.lib.WordArray.random(128 / 8);
        const key = CryptoJS.PBKDF2(secretKey, salt, { keySize: 256 / 32 });
        const iv = CryptoJS.lib.WordArray.random(128 / 8);
        const ciphertext = CryptoJS.AES.encrypt(JSON.stringify(data), key, {
          iv: iv,
        });

        const saltString = CryptoJS.enc.Base64.stringify(salt);
        const ivString = CryptoJS.enc.Base64.stringify(iv);
        const ciphertextString = ciphertext.toString();

        return {
          salt: saltString,
          iv: ivString,
          ciphertext: ciphertextString,
        };
      },

      /**
       * Encrypts an object using a secret key.
       * @param {Object} data - The object to be encrypted.
       * @param {string} secretKey - The secret key to encrypt the object with.
       * @returns {Object} The encrypted object, along with the salt and iv used during encryption. Each of these three properties is a Base64-encoded string.
       * @property {string} salt - The random salt used during encryption, Base64-encoded.
       * @property {string} iv - The random initialization vector (iv) used during encryption, Base64-encoded.
       * @property {string} ciphertext - The encrypted object, Base64-encoded.
       */
      decryptObject: (
        storedSaltString,
        storedIvString,
        storedCiphertextString,
        password
      ) => {
        // Convert the stored salt and IV back to WordArray
        const storedSalt = CryptoJS.enc.Base64.parse(storedSaltString);
        const storedIv = CryptoJS.enc.Base64.parse(storedIvString);
        // Derive the key using the stored salt and original password
        const storedKey = CryptoJS.PBKDF2(password, storedSalt, {
          keySize: 256 / 32,
        });

        // Decrypt the ciphertext using the derived key and stored IV
        const decrypted = CryptoJS.AES.decrypt(
          storedCiphertextString,
          storedKey,
          { iv: storedIv }
        );

        // Convert the decrypted ciphertext to a plaintext string
        const decryptedPlaintext = decrypted.toString(CryptoJS.enc.Utf8);
        console.log("Decrypted plaintext:", decryptedPlaintext);

        return decryptedPlaintext;
      },
    },
  },
};

module.exports = MecenateHelper;
