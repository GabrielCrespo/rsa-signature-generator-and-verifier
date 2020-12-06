const { generateKeyPairSync, sign, verify, constants, privateDecrypt, publicEncrypt } = require("crypto");
const { readFileSync, writeFileSync} = require("fs");

class RSA {

  generatePublickAndPrivateKeys = (keyLength) => {
    const keyOptions = [
      {
        modulusLength: keyLength,
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
          cipher: "aes-256-cbc",
          passphrase: "passphrase",
        },
      },
    ];

    const [{ publicKey, privateKey }] = keyOptions.map((options) =>
      generateKeyPairSync("rsa", options)
    );

    writeFileSync("../files/public.pub", publicKey.toString('hex'));
    writeFileSync("../files/private.key", privateKey.toString('hex'));
  };

  encryptInformation = (data) => {
    const encryptedData = publicEncrypt(
      {
        key: readFileSync('../files/public.pub'),
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha3-256",
      },
      Buffer.from(data)
    );
    writeFileSync("../files/encrypt.txt", encryptedData.toString('hex'));
    return encryptedData;
  };

  decryptInformation = (encryptedData) => {
    const decryptedData = privateDecrypt(
      {
        key: readFileSync('../files/private.key'),
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha3-256",
        passphrase: "passphrase",
      },
      encryptedData
    );
    writeFileSync("../files/decrypt.txt", decryptedData.toString('utf-8'));
    return decryptedData;
  };

  generateSignature = (fileData) => {
    const signature = sign("sha3-256", Buffer.from(fileData), {
      key: readFileSync('../files/private.key'),
      padding: constants.RSA_PKCS1_PSS_PADDING,
      passphrase: 'passphrase',
    });
    writeFileSync("../files/signature.txt", signature.toString('hex'));
    return signature;
  };

  verifySignature = (fileData, signature) => {
    const isVerified = verify(
      "sha3-256",
      Buffer.from(fileData),
      {
        key: readFileSync('../files/public.pub'),
        padding: constants.RSA_PKCS1_PSS_PADDING,
      },
      signature
    );
    return isVerified;
  };
}

module.exports = RSA;