/*
Copyright fr000gs
Licensed under GNU AGPL 3.0
made for my personal use
*/
import { fromByteArray, toByteArray, byteLength }
from "./b64.js";
import { ECB } from "./ecb.js";

var encoder = new TextEncoder();
var decoder = new TextDecoder();

function aesecbenc(text, key) {
  var textBytes = encoder.encode(text);
  var keyBytes = encoder.encode(key); // Ensure key is byte array
  var aesEcb = new ECB(keyBytes);
  
  var encryptedBytes = new Uint8Array(textBytes.length);
  aesEcb.encrypt(textBytes, encryptedBytes);

  return fromByteArray(encryptedBytes);
}

function aesecbdec(encryptedBytes, key) {
  var keyBytes = encoder.encode(key); // Ensure key is byte array
  var aesEcb = new ECB(keyBytes);
  
  var decryptedBytes = new Uint8Array(encryptedBytes.length);
  aesEcb.decrypt(encryptedBytes, decryptedBytes);

  return decoder.decode(decryptedBytes);
}


function longtext(text) {
  var textBytes = encoder.encode(text);
  var chunks = [];

  for (var i = 0; i < textBytes.length; i += 16) {
    var chunk = textBytes.slice(i, i + 16);
    chunks.push(cut16(decoder.decode(chunk))); // Apply proper padding
  }

  return chunks;
}

function cut16(text) {
  var te = '';
  for (var i = 0;
    (i < 16) && (i < text.length); i++) {
    te = te + text[i];
  }
  return te.padEnd(16);
}
function encbtns() {
  var text = longtext(document.getElementById("inputtext").value);
  var key = cut16(document.getElementById("key").value);
  var encryptedText = text.map(chunk => aesecbenc(chunk, key)).join('@@@');
  document.getElementById("encdec").innerHTML = encryptedText;
}

document.getElementById("encbtn")
  .addEventListener("click", encbtns, false);

function cutter(text) {
  return text.split('@@@').map(chunk => chunk.trim()).filter(chunk => chunk.length > 0);
}

function decbtns() {
  var text = cutter(document
    .getElementById("inputtext").value);
  var key = cut16(document
    .getElementById("key").value);
  var bytes = '';
  for (var i = 0; i < text.length; i++) {
    bytes = bytes + aesecbdec(
      toByteArray(text[i]), key);
  }
  document.getElementById("encdec")
    .innerHTML = bytes;
}

document.getElementById("decbtn")
  .addEventListener("click", decbtns, false);

function copyOutput() {
  navigator.clipboard.writeText(
    document.getElementById("encdec").textContent
  ).then(() => alert("Copied to clipboard!"))
   .catch(err => console.error("Copy failed:", err));
}


document.getElementById("copyoutput")
  .addEventListener("click", copyOutput, false);
