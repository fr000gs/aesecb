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
  const paddedTextBytes = pkcs7Pad(text, 16);

  const keyBytes = encoder.encode(key);
  const aesEcb = new ECB(keyBytes);

  const encryptedBytes = new Uint8Array(paddedTextBytes.length);

  for (let i = 0; i < paddedTextBytes.length; i += 16) {
    const block = paddedTextBytes.slice(i, i + 16);

    const encryptedBlock = new Uint8Array(16);
    aesEcb.encrypt(block, encryptedBlock);

    encryptedBytes.set(encryptedBlock, i);
  }
  return fromByteArray(encryptedBytes);
}

function aesecbdec(encryptedBytes, key) {
  const keyBytes = encoder.encode(key);
  const aesEcb = new ECB(keyBytes);

  const decryptedPaddedBytes = new Uint8Array(encryptedBytes.length);
  for (let i = 0; i < encryptedBytes.length; i += 16) {
    const block = encryptedBytes.slice(i, i + 16);
    const decryptedBlock = new Uint8Array(16);
    aesEcb.decrypt(block, decryptedBlock);
    decryptedPaddedBytes.set(decryptedBlock, i);
  }

  const unpaddedBytes = pkcs7Unpad(decryptedPaddedBytes);
  return decoder.decode(unpaddedBytes);
}

function longtext(text) {
  var textBytes = encoder.encode(text);
  var chunks = [];

  for (var i = 0; i < textBytes.length; i += 16) {
    var chunk = textBytes.slice(i, i + 16);
    chunks.push(cut16(decoder.decode(chunk)));
  }

  return chunks;
}

function pkcs7Pad(text, blockSize = 16) {

  const textBytes = encoder.encode(text);

  const padLength = blockSize - (textBytes.length % blockSize) || blockSize;
  const padded = new Uint8Array(textBytes.length + padLength);

  padded.set(textBytes);

  padded.fill(padLength, textBytes.length);
  return padded;
}

function pkcs7Unpad(paddedBytes) {
  const padLength = paddedBytes[paddedBytes.length - 1];
  if (padLength < 1 || padLength > 16) {
    throw new Error("Invalid padding");
  }

  for (let i = paddedBytes.length - padLength; i < paddedBytes.length; i++) {
    if (paddedBytes[i] !== padLength) {
      throw new Error("Invalid padding");
    }
  }

  return paddedBytes.slice(0, paddedBytes.length - padLength);
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
  const inputText = document.getElementById("inputtext").value;
  const key = cut16(document.getElementById("key").value);
  const encryptedText = aesecbenc(inputText, key);
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
