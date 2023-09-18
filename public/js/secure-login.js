const scheme = 'http://';
const origin = 'localhost:3000';
const path = '/getAuthKey';
const loginPath = '/login';
 
const str2ab = str => {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}
 
const generateKey =  async () => await window.crypto.subtle.generateKey(
    {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" }
    },
    true,
    ["encrypt", "decrypt"]
);
 
const importKey = async (pem, opt) => {
    const binaryDerString = window.atob(pem);
    const binaryDer = str2ab(binaryDerString);
    return await window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true,
        opt
    );
}
 
const encryptMessage = async (key, msg) => {
    return await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP",
            hash: {name: 'SHA-256'}
        },
        key,
        str2ab(msg)
    )
}
 
const decryptMessage = async (key, msg) => {
    return await window.crypto.subtle.decrypt(
        {
          name: "RSA-OAEP",
          hash: {name: 'SHA-256'}
        },
        key,
        msg
    );
}
 
 
function arrayBufferToBase64String(arrayBuffer) {
    var byteArray = new Uint8Array(arrayBuffer)
    var byteString = ''
    for (var i=0; i<byteArray.byteLength; i++) {
      byteString += String.fromCharCode(byteArray[i])
    }
    return btoa(byteString)
}
 
async function encryptCredentials(username, password) {
    try {
        let response = await fetch(scheme + origin + path);
        let publicKeyHash = await response.text();
        let publicKey = await importKey(publicKeyHash, ["encrypt"]);
 
        let msg = username + ':' + password;
        let msgEncrypted = await encryptMessage(publicKey, msg);
        return arrayBufferToBase64String(msgEncrypted);
    } catch(e){
        console.log(e)
    }
}