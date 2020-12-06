const RSASignVer = require("./RSASignatureGeneratorVerifier");
const readLine = require("readline");
const fs = require("fs");
const process = require("process");

const consoleReader = readLine.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const rsaSignVer = new RSASignVer();

process.stdout.write("\u001B[2J\u001B[0;0f");

consoleReader.question(
  `Escolha uma opção: 

      1 - Somente gerar chaves pública e privada com tamanho de 2048 bytes.
      2 - Cifrar e decifrar o conteúdo de um arquivo.
      3 - Assinar e verificar o conteúdo de um arquivo.

      Pressione qualquer tecla para sair.

      : `,
  (answer) => {
    let response = parseInt(answer);
    process.stdout.write("\u001B[2J\u001B[0;0f");
    switch (response) {
      case 1:
        console.log("Gerando as chaves pública e privada de 2048 bytes...");
        rsaSignVer.generatePublickAndPrivateKeys(2048);
        console.log("Chaves geradas com sucesso e salvas em arquivos .key e .pub");
        break;
      case 2:
        console.log("Gerando as chaves pública e privada de 2048 bytes...");
        rsaSignVer.generatePublickAndPrivateKeys(2048);
        console.log("Chaves geradas com sucesso e salvas em arquivos .key e .pub\n");

        var fileDataCipher = fs.readFileSync("../files/teste.txt");
        console.log("Cifrando os dados do arquivo...\n");

        const encryptFileData = rsaSignVer.encryptInformation(fileDataCipher);
        console.log(
          "Os dados dos arquivo foram cifrados: ",
          encryptFileData.toString("hex"),
          "\n"
        );

        console.log("Decifrando os dados do arquivo...\n");
        const decryptFileData = rsaSignVer.decryptInformation(encryptFileData);
        console.log(
          "Os dados dos arquivo foram decifrados: " +
            decryptFileData.toString("utf-8")
        );
        break;

      case 3:
        console.log("Gerando as chaves pública e privada de 2048 bytes...");
        rsaSignVer.generatePublickAndPrivateKeys(2048);
        console.log("Chaves geradas com sucesso e salvas em arquivos .key e .pub\n");

        const fileDataSignature = fs.readFileSync("../files/teste.txt");
        console.log(
          "Cifrando e gerando assinatura dos dados do arquivo...\n");

        const signatureFileData = rsaSignVer.generateSignature(
          fileDataSignature
        );
        console.log("Gerando o hash sha3-256 dos dados do arquivo...");
        console.log("Hash gerado com sucesso!\n");
        console.log("Gerando a assinatura a partir do valor do hash...");
        console.log(
          "Assinatura gerada: ",
          signatureFileData.toString("hex"),
          "\n"
        );

        console.log("Verificando a assinatura recebida...");
        const verifySignFileData = rsaSignVer.verifySignature(
          fileDataSignature,
          signatureFileData
        );

        const isVerified = verifySignFileData
          ? "Assinatura verificada com sucesso!"
          : "Assinatura inválida";
        console.log(isVerified);

        break;
      default:
        process.exit();
    }
    consoleReader.close();
  }
);
