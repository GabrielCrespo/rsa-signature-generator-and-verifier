const { generateKeyPairSync, sign, verify, constants } = require("crypto");
const { writeFileSync, readFileSync } = require("fs");

// Reading the file data as string using utf-8 encoding
const fileData = readFileSync("../files/test.txt", "utf-8");
console.log(fileData)

const keyOptions = [
  {
    modulusLength: 1024,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase: "TopSecret",
    },
  },
];

const [
  { publicKey: publicKey, privateKey: privateKey },
] = keyOptions.map((options) => generateKeyPairSync("rsa", options));

// Writing the public and private keys into two separated files
writeFileSync("public.pub", publicKey.toString("hex"));
writeFileSync("private.key", privateKey.toString("hex"));

/*
 *  Transforming the file data to a hash sha3-256
 *  Generating the hash signature with the private key and RSA-OEAP padding
 *  Passphrase is used to decrypt the private key that is encrypt in aes-256-cbc
 */
const signature = sign("sha3-256", Buffer.from(fileData), {
  key: privateKey,
  padding: constants.RSA_PKCS1_PSS_PADDING,
  passphrase: "TopSecret",
});

const isVerified = verify(
  "sha3-256",
  Buffer.from(fileData),
  {
    key: publicKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
  },
  signature
);

console.log("signature verified:", isVerified);
