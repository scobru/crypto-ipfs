const fernet = require("fernet");
const tweetnacl = require("tweetnacl");
const pbkdf2 = require("pbkdf2");
const getRandomValues = require("get-random-values");
const multihash = require("multihashes");
const sha256_cid = require("ipfs-only-hash");
const ethers = require("ethers");
const crypto = require("asymmetric-crypto");
const CryptoJS = require("crypto-js");

const MAX_UINT32 = Math.pow(2, 32) - 1;
const MAX_UINT8 = Math.pow(2, 8) - 1;
const FERNET_SECRET_LENGTH = 32;
const NONCE_LENGTH = 24;

const randomNumber = () => {
  if (typeof window === "undefined") {
    return getRandomValues(new Uint8Array(1))[0] / MAX_UINT8;
  }
  return getRandomValues(new Uint32Array(1))[0] / MAX_UINT32;
};

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

/// Convert multihash from input of specified type to multihash buffer object
/// Valid input types:
/// - 'raw': raw data of any form - will caculate chunked ipld content id using sha2-256
/// - 'sha2-256': hex encoded sha2-256 hash - will append multihash prefix
/// - 'hex': hex encoded multihash
/// - 'b58': base58 encoded multihash
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

/// Convert multihash from buffer object to output of specified type
/// Valid output types:
/// - 'prefix': hex encoded multihash prefix
/// - 'digest': hex encoded hash
/// - 'hex': hex encoded multihash
/// - 'b58': base58 encoded multihash
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

const MecenateHelper = {
  multihash: async ({ input, inputType, outputType }) =>
    multihashTo(await multihashFrom(input, inputType), outputType),
  constants: {
    TOKEN_TYPES: {
      NaN: 0,
      MUSE: 1,
      DAI: 2,
    },
  },
  encodeCreateCall: (templateABI, abiValues) => {
    const abi = new ethers.utils.Interface(templateABI);
    const calldata = abi.functions.initialize.encode(abiValues);
    return calldata;
  },
  crypto: {
    symmetric: {
      generateKey: () => {
        let key = Buffer.from(randomString()).toString("base64");
        let secret = fernet.decode64toHex(key);
        while (secret.length !== fernet.hexBits(256)) {
          key = Buffer.from(randomString()).toString("base64");
          secret = fernet.decode64toHex(key);
        }
        return key;
      },
      encryptMessage: (secretKey, msg) => {
        const secret = new fernet.Secret(secretKey);
        const token = new fernet.Token({ secret, ttl: 0 });
        return token.encode(msg);
      },
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
      generateKeyPair: (sig, salt) =>
        tweetnacl.box.keyPair.fromSecretKey(
          pbkdf2.pbkdf2Sync(sig, salt, 1000, 32)
        ),
      generateNonce: () => tweetnacl.randomBytes(NONCE_LENGTH),
      encryptMessage: (msg, nonce, publicKey, secretKey) => {
        const encoder = new TextEncoder();
        const encodedMessage = encoder.encode(msg);
        return tweetnacl.box(encodedMessage, nonce, publicKey, secretKey);
      },
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
        encryptMessage: (msg, nonce, secretKey) => {
          const encoder = new TextEncoder();
          const encodedMessage = encoder.encode(msg);
          return tweetnacl.secretbox(encodedMessage, nonce, secretKey);
        },
        decryptMessage: (box, nonce, secretKey) => {
          const decoder = new TextDecoder();
          const encodedMessage = tweetnacl.secretbox.open(
            box,
            nonce,
            secretKey
          );
          return decoder.decode(encodedMessage);
        },
      },
      keyPair: () => {
        const keyPair = crypto.keyPair();
        return keyPair;
      },
      fromSecretKey: (secretKey) => {
        return crypto.fromSecretKey(secretKey);
      },
      encrypt: (data, theirPublicKey, mySecretKey) => {
        return crypto.encrypt({
          message: data,
          publicKey: theirPublicKey,
          secretKey: mySecretKey,
        });
      },
      decrypt: (data, theirPublicKey, mySecretKey) => {
        return crypto.decrypt({
          message: data,
          publicKey: theirPublicKey,
          secretKey: mySecretKey,
        });
      },
      sign: (data, secretKey) => {
        return crypto.sign(data, secretKey);
      },
      verify: (data, signature, publicKey) => {
        return crypto.verify(data, signature, publicKey);
      },
    },
    aes: {
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
