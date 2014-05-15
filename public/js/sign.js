


function sign(privateKey, message) {
    // Crea el objeto de la clave RSA a partir de la cadena pasada como parámetro
    var rsa = new RSAKey();
    rsa.readPrivateKeyFromPEMString(privateKey);
    // Prepara el objeto para realizar la firma usando SHA256 como algoritmo
    // de hashing y RSA para el cifrado asimétrico
    var sig = new KJUR.crypto.Signature(
        {"alg": "SHA256withRSA", "prov": "cryptojs/jsrsa"});
    // Inicializa el objeto de firma con la clave pública
    sig.initSign(rsa);
    // Actualiza la firma con el contenido del mensaje
    sig.updateString(message);
    // Y finalmente devuelve la firma
    return sig.sign();
}

function verify(message, signature, publicKeyString) {
    var publicKey = KEYUTIL.getKey(publicKeyString);
    // Prepara el objeto para verificar la firma usando SHA256 como algoritmo
    // de hashing y RSA para el cifrado asimétrico
    var sig = new KJUR.crypto.Signature(
        {"alg": "SHA256withRSA", "prov": "cryptojs/jsrsa"});
    // Inicializa el objeto de firma con la clave pública
    sig.initVerifyByPublicKey(publicKey);
    // Actualiza el objeto de firma con el mensaje en texto plano
    sig.updateString(message);
    // Y finalmente devuelve el resultado de verificar la firma
    return sig.verify(signature);
}

function generate(keySize) {
    if(!keySize) {
        keySize = "512";
    }
    var keyPair = KEYUTIL.generateKeypair("RSA", keySize);
    var pubKey = KEYUTIL.getKey(keyPair.pubKeyObj);
    var privKey = KEYUTIL.getKey(keyPair.prvKeyObj);

    privKey.isPrivate = true; //bug: https://github.com/kjur/jsrsasign/issues/53
    var privateKey = KEYUTIL.getPEM(keyPair.prvKeyObj, "PKCS1PRV");
    var publicKey= KEYUTIL.getPEM(pubKey);

    return {"privateKey": privateKey, "publicKey": publicKey};
}