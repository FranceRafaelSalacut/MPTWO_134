
//Global Variables 
var keyGenerate = false
var encrypted = false
var receiverPublicKey
var receiverPrivateKey
var senderPublicKey
var senderPrivateKey

function generateKeys(){
    if(keyGenerate){
        alert("Keys already generated")
        return
    }
        
    //Generate RSA keys for receiver
    receiverKeyPair = forge.pki.rsa.generateKeyPair()
    receiverPublicKey = receiverKeyPair.publicKey
    receiverPrivateKey = receiverKeyPair.privateKey

    //Display receiver key pair
    document.getElementById("EPbK").textContent = forge.pki.publicKeyToPem(receiverPublicKey)
    document.getElementById("EPvk").textContent = forge.pki.publicKeyToPem(receiverPrivateKey)

    // Generate RSA keys for sender
    senderKeyPair = forge.pki.rsa.generateKeyPair()
    senderPublicKey = senderKeyPair.publicKey
    senderPrivateKey = senderKeyPair.privateKey
        
    //Display sender key pair
    document.getElementById("SPbK").textContent = forge.pki.publicKeyToPem(senderPublicKey)
    document.getElementById("SPvk").textContent = forge.pki.publicKeyToPem(senderPrivateKey)

    console.log("CLICK")
    keyGenerate = true
    alert("Key Pairs Generated")
}

function resetKeys(){
    if(keyGenerate){
        keyGenerate = false
    }

    msg = "Generate New Keys"
    document.getElementById("EPbK").textContent = msg
    document.getElementById("EPvk").textContent = msg
    document.getElementById("SPbK").textContent = msg
    document.getElementById("SPvk").textContent = msg
    
}

function encryptMessage(){
    if(!keyGenerate){
        alert("No keys Generated")
        return
    }

    //Get the user input message
    message = document.getElementById("message").value

    if(message == ""){
        alert("Enter A Message")
        return
    }

    document.getElementById("message").readOnly = true

    //Encrypt the user message using RSA-OAEP
    encryptedMessage = receiverPublicKey.encrypt(message, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: forge.mgf1.create(forge.md.sha256.create())
        })

    
    //Displaying the encrypted message
    document.getElementById("encryptedMessage").textContent = encryptedMessage
    
    
    //Sign the encrypted message
    md = forge.md.sha256.create()
    md.update(encryptedMessage, 'utf8')
    signedMessage = senderPrivateKey.sign(md)
    
    //Displaying the signed message
    document.getElementById("signedEncryptedMessage").textContent = signedMessage

    encrypted = true
}

function resetMessage(){
    if(encrypted){
        alert("Resetting Encrypted Message")
    }

    document.getElementById("message").readOnly = false
    document.getElementById("message").value = ""
    encrypted = false
    document.getElementById("encryptedMessage").textContent = ""
    document.getElementById("signedEncryptedMessage").textContent = ""
    document.getElementById("verifyMessage").textContent = ""
    document.getElementById("decryptMessage").textContent = ""
}

function randomMessage(){
    if(encrypted){
        resetMessage()
    }

    characters ='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    charactersLength = characters.length
    result = ' '
    for ( let i = 0; i < Math.floor((Math.random()*10) + 140); i++ ) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength))
    }

    document.getElementById("message").value = result
}

function decryptMessage(){
    if(!encrypted){
        alert("Encrypt A Message First!")
        return
    }

    encryptedMessage = document.getElementById("encryptedMessage").textContent
    signedMessage = document.getElementById("signedEncryptedMessage").textContent

    // Verify the signature using the sender's public key
    verifyMd = forge.md.sha256.create()
    verifyMd.update(encryptedMessage, 'utf8')
    isValid = senderPublicKey.verify(verifyMd.digest().bytes(), signedMessage)
 
    if (isValid) {
        console.log('Signature is valid')
        document.getElementById("verifyMessage").textContent = "Signature is Valid"
    
        // Decrypt the message using the receiver's private key
        decryptedMessage = receiverPrivateKey.decrypt(encryptedMessage, 'RSA-OAEP', {
            md: forge.md.sha256.create(),
            mgf1: forge.mgf1.create(forge.md.sha256.create())
        })
 
        document.getElementById("decryptMessage").textContent = decryptedMessage
    } else {
        console.log('Signature verification failed')
        document.getElementById("verifyMessage").textContent = "Signature verification failed"
    }

    decrypted = receiverPrivateKey.decrypt(encryptedMessage, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: forge.mgf1.create(forge.md.sha256.create())
    })

    if(document.getElementById("message").value == decrypted ){
        console.log("YEYAA")
    }else{
        console.log("DAMN DONE DIS SHIT")
    }
}


