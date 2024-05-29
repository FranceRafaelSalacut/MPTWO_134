
let keyGenerate = false

function generate(){
    if(!keyGenerate){

        encryptionKeyPair = forge.pki.rsa.generateKeyPair();
        encryptionPublicKey = encryptionKeyPair.publicKey;
        encryptionPrivateKey = encryptionKeyPair.privateKey;

        document.getElementById("EPbK").textContent = forge.pki.publicKeyToPem(encryptionPublicKey)
        document.getElementById("EPvk").textContent = forge.pki.publicKeyToPem(encryptionPrivateKey)

        signingKeyPair = forge.pki.rsa.generateKeyPair(2048);
        signingPublicKey = signingKeyPair.publicKey;
        signingPrivateKey = signingKeyPair.privateKey;

        document.getElementById("SPbK").textContent = forge.pki.publicKeyToPem(signingPublicKey)
        document.getElementById("SPvk").textContent = forge.pki.publicKeyToPem(signingPrivateKey)

        console.log("CLICK")
        keyGenerate = true
    }else{
        alert("Keys already generated")
    }   
}

function resetKeys(){
    if(keyGenerate){
        keyGenerate = false
        msg = "Generate new Keys"
        document.getElementById("EPbK").textContent = msg
        document.getElementById("EPvk").textContent = msg
        document.getElementById("SPbK").textContent = msg
        document.getElementById("SPvk").textContent = msg
    }
}



function do_this(){
    // Generate RSA keys for encryption
    
    

    // Generate RSA keys for signing
    

    // Message to be encrypted and signed
    const message = 'Secret Message';

    // Encrypt the message using RSA-OAEP
    const encryptedMessage = encryptionPublicKey.encrypt(message, 'RSA-OAEP', {
    md: forge.md.sha256.create(),
    mgf1: forge.mgf1.create(forge.md.sha256.create())
    });

    // Sign the encrypted message using the signing private key
    const md = forge.md.sha256.create();
    md.update(encryptedMessage, 'utf8');
    const signature = signingPrivateKey.sign(md);

    // Transmit encryptedMessage and signature

    // On the receiver side:

    // Verify the signature using the sender's public key
    const verifyMd = forge.md.sha256.create();
    verifyMd.update(encryptedMessage, 'utf8');
    const isValid = signingPublicKey.verify(verifyMd.digest().bytes(), signature);

    if (isValid) {
    console.log('Signature is valid.');

    // Decrypt the message using the receiver's private key
    const decryptedMessage = encryptionPrivateKey.decrypt(encryptedMessage, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: forge.mgf1.create(forge.md.sha256.create())
    });

    console.log('Decrypted message:', decryptedMessage);
    } else {
    console.log('Signature verification failed.');
    }
}