/*
Usage: Execute groovy script however you can.
Encryption details: https://github.com/PrivateBin/PrivateBin/wiki/Encryption-format
 */
import groovy.json.JsonBuilder
import groovy.json.JsonSlurper
import java.nio.file.Files
import java.nio.file.Paths
import java.security.spec.KeySpec
import java.util.zip.Deflater
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.HttpsURLConnection
import org.bitcoinj.core.Base58

//Required parameters
String pasteServerURL = "https://cpaste.org"        //  Paste URL
String expire = "1week"                             //  Options: 5min, 10min, 1hour, 1day, 1week, 1month, 1year, never
String pasteFormat = "plaintext"                    //  Options: plaintext, syntaxhighlighting, markdown
String compression = "zlib"                         //  Options: none, zlib
int burnAfterReading = 0                            //  Options: 0 - Off, 1 - On
int openDiscussion = 0                              //  Options: 0 - Off, 1 - On

//Optional parameters
String message = "Hello world"                      //  Message to paste to PrivateBin, leave quotes empty for no message
String localAttachmentFilename = ""                 //  Location of local file to attach, leave quotes empty for no file
String pasteAttachmentFilename = ""                 //  Paste attachment name, leave quotes empty for no file
String plaintextFileLocation = ""                   //  Read file contents into paste, leave quotes empty no no file
String userPastePassword = ""                       //  Set paste password, leave quotes empty for no password


// Burn after reading cannot be active if opendiscussion is.
if (burnAfterReading == 1){openDiscussion = 0}

//  Test server
HttpsURLConnection testPasteServer = (HttpsURLConnection) new URL(pasteServerURL).openConnection()
int testRC = testPasteServer.getResponseCode()
testPasteServer.disconnect()
if (testRC != 200){return}

// Generate password
KeyGenerator keyGen = KeyGenerator.getInstance("AES")
keyGen.init(192)
randomPassword = Base64.getEncoder().encodeToString(keyGen.generateKey().getEncoded())
String customPassword = "${randomPassword}${userPastePassword}"

// Generate IV
byte[] cipherIVBytes = new byte[16]
new Random().nextBytes(cipherIVBytes)
String cipherIVEncoded = Base64.getEncoder().encodeToString(cipherIVBytes)

// Generate salt
byte[] kdfSaltBytes = new byte[8]
new Random().nextBytes(kdfSaltBytes)
String kdfSaltEncoded = Base64.getEncoder().encodeToString(kdfSaltBytes)

// Build message to encrypt
String pasteData = new String()
if(!plaintextFileLocation && (!localAttachmentFilename || !pasteAttachmentFilename) && !message){
    println("No data to paste.")
    return
}
if (!plaintextFileLocation && (!localAttachmentFilename || !pasteAttachmentFilename)){
    JsonBuilder jsonMessage = new JsonBuilder() paste: message
    pasteData = jsonMessage.toString()
}
if(plaintextFileLocation) {
    String output = new String(Files.readAllBytes(Paths.get(plaintextFileLocation)))
    JsonBuilder jsonMessage = new JsonBuilder() paste: "${message}\n${output}"
    pasteData = jsonMessage.toString()
    message = "${message}${output}"
}
if(localAttachmentFilename && pasteAttachmentFilename) {
    byte[] attachmentBytes = Files.readAllBytes(Paths.get(localAttachmentFilename))
    String attachmentBase64 = Base64.getEncoder().encodeToString(attachmentBytes)
    String mimeType = Files.probeContentType(Paths.get(localAttachmentFilename))
    JsonBuilder jsonMessage = new JsonBuilder() paste: message, attachment: "data:${mimeType};base64,${attachmentBase64}", attachment_name: pasteAttachmentFilename
    pasteData = jsonMessage.toString()
}

// Compression
byte[] pasteDataBytes
if (compression == "zlib") {
    Deflater zipDeflater = new Deflater()
    ByteArrayOutputStream stream = new ByteArrayOutputStream()
    zipDeflater.setInput(pasteData.getBytes())
    zipDeflater.finish()
    byte[] buffer = new byte[1024]
    while (!zipDeflater.finished()) {
        int count = zipDeflater.deflate(buffer)
        stream.write(buffer, 0, count)
    }
    byte[] output
    output = stream.toByteArray()
    stream.close()
    zipDeflater.end()
    //Need to remove the header
    pasteDataBytes = Arrays.copyOfRange(output, 2, output.size() - 4)
} else {
    pasteDataBytes = pasteData.getBytes()
}

// Generate secret key for cipher
SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(customPassword.toCharArray(), kdfSaltBytes, 100000, 256)
SecretKey secret = new SecretKeySpec(factory.generateSecret(passwordBasedEncryptionKeySpec).getEncoded(), "AES")

// Cipher AAD
ArrayList gcmTagData = [[cipherIVEncoded, kdfSaltEncoded, 100000, 256, 128, "aes", "gcm", compression], pasteFormat, openDiscussion, burnAfterReading]
String gcmTagString = new groovy.json.JsonBuilder(gcmTagData).toString()
byte[] gcmBytes = gcmTagString.getBytes()

// Generate cipher text
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding")
GCMParameterSpec spec = new GCMParameterSpec(128, cipherIVBytes)
cipher.init(Cipher.ENCRYPT_MODE, secret, spec)
cipher.updateAAD(gcmBytes)
byte[] cipherTextBytes = cipher.doFinal(pasteDataBytes)
String cipherText = Base64.getEncoder().encodeToString(cipherTextBytes)

// Create POST payload
JsonBuilder expireJSON = new JsonBuilder() expire:expire
JsonBuilder payloadJson = new JsonBuilder() v: 2, adata: gcmTagData, ct:cipherText, meta: expireJSON.content
String payload = payloadJson.toString()

// POST Request
HttpsURLConnection pasteRequest = (HttpsURLConnection) new URL(pasteServerURL).openConnection()
pasteRequest.setRequestMethod("POST")
pasteRequest.setDoOutput(true)
pasteRequest.setRequestProperty('X-Requested-With', 'JSONHttpRequest')
pasteRequest.getOutputStream().write(payload.getBytes())

// Server response
int responseCode = pasteRequest.getResponseCode()
println("Server response: ${responseCode}")
if (responseCode == 200){
    Object responseJSON = new JsonSlurper().parseText(pasteRequest.getInputStream().getText())
    if(responseJSON["status"] == 0){
        String pasteURL = responseJSON["url"]
        String deleteToken = responseJSON["deletetoken"]
        String finalURL = "${pasteServerURL}${pasteURL}#${Base58.encode(randomPassword.getBytes())}"
        String deleteURL = "${pasteServerURL}${pasteURL}&deletetoken=${deleteToken}"
        println("Success.")
        println("Paste URL: ${finalURL}")
        println("Delete URL: ${deleteURL}")
    } else {
        println(responseJSON["message"])
    }
}
pasteRequest.disconnect()
