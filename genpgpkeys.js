const fs = require('fs');

const openpgp = require('openpgp')

const generateKeys = async (name, email, passphrase) => {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'rsa',
    rsaBits: 4096,
    userIDs: [{name, email}],
    passphrase,
  });
  return { privateKey, publicKey };
};

const handleGenerateKeys = async (passphrase) => {
  let newKeys = { undefined, undefined }
  try {
    newKeys = await generateKeys('ranker', 'ranker@duke.efu', passphrase);
    // Persist the public key to your server and the private key (encrypted) to local storage or server.
  } catch (error) {
    console.error('Key generation failed:', error);
  }
  return newKeys
};

const decryptMessage = async (encryptedString) => {

  const privateKeyArmored = fs.readFileSync('./private-key.asc', 'utf8')
  const passphrase = fs.readFileSync('./passphrase.txt', 'utf8')

//   console.log(encryptedString)
//   console.log(privateKeyArmored)
//   console.log(passphrase)

  try {
 
    // Step 1: Read the armored private key string
    const privateKey = await openpgp.readKey({ armoredKey: privateKeyArmored });

    // Step 2: Decrypt the key with the passphrase
    const unlockedPrivateKey = await openpgp.decryptKey({
        privateKey,
        passphrase,
    });

    const encryptedMessage = await openpgp.readMessage({ armoredMessage : encryptedString })

    const decrypted = await openpgp.decrypt({
        message: encryptedMessage,
        decryptionKeys: unlockedPrivateKey,
    });

    // console.log(decrypted.data)
    return decrypted.data;
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('Decryption failed');
  }
};

module.exports = {
  handleGenerateKeys: handleGenerateKeys,
  decryptMessage: decryptMessage
};

