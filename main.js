
//Global Variables 
var keyGenerate = false
var encryptionPublicKey
var encryptionPrivateKey
var signingPublicKey
var signingPrivateKey

function generateKeys(){
    if(keyGenerate){
        alert("Keys already generated")
        return
    }
        
    //Generate RSA keys for encryption
    encryptionKeyPair = forge.pki.rsa.generateKeyPair();
    encryptionPublicKey = encryptionKeyPair.publicKey;
    encryptionPrivateKey = encryptionKeyPair.privateKey;

    //Display Encryption key pair
    document.getElementById("EPbK").textContent = forge.pki.publicKeyToPem(encryptionPublicKey)
    document.getElementById("EPvk").textContent = forge.pki.publicKeyToPem(encryptionPrivateKey)

    // Generate RSA keys for signing
    signingKeyPair = forge.pki.rsa.generateKeyPair(2048);
    signingPublicKey = signingKeyPair.publicKey;
    signingPrivateKey = signingKeyPair.privateKey;
        
    //Display Signing key pair
    document.getElementById("SPbK").textContent = forge.pki.publicKeyToPem(signingPublicKey)
    document.getElementById("SPvk").textContent = forge.pki.publicKeyToPem(signingPrivateKey)

    console.log("CLICK")
    keyGenerate = true
}

function resetKeys(){
    if(keyGenerate){
        keyGenerate = false
        msg = "Generate New Keys"
        document.getElementById("EPbK").textContent = msg
        document.getElementById("EPvk").textContent = msg
        document.getElementById("SPbK").textContent = msg
        document.getElementById("SPvk").textContent = msg
    }
}

function encryptMessage(){
    if(!keyGenerate){
        alert("No keys Generated")
        return
    }
    //Get the user input message
    message = document.getElementById("message").value
    encrypted = encryptionPublicKey.encrypt(message, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: forge.mgf1.create(forge.md.sha256.create())
        });

    document.getElementById("encryptedMessage").textContent = encrypted
    
    console.log(encrypted)
}

function decryptMessage(){
    encryptedMessage = document.getElementById("encryptedMessage").textContent

    decrypted = encryptionPrivateKey.decrypt(encryptedMessage, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: forge.mgf1.create(forge.md.sha256.create())
    });

    if(document.getElementById("message").value == decrypted ){
        console.log("YEYAA")
    }else{
        console.log("DAMN DONE DIS SHIT")
    }
    console.log(decrypted)
}

function randomMessage(){
    characters ='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    charactersLength = characters.length;
    result = ' '
    for ( let i = 0; i < Math.floor((Math.random()*10) + 140); i++ ) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }

    document.getElementById("message").value = result

    console.log(result)
}



function do_this(){

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