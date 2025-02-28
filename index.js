/*
Copyright fr000gs
Licensed under GNU AGPL 3.0
made for my personal use
*/
import { fromByteArray, toByteArray } from "./b64.js";
import { ECB } from "./ecb.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

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
  // Return first 16 characters, padded with spaces if necessary
  return text.slice(0, 16).padEnd(16);
}

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

function encbtns() {
  const inputText = document.getElementById("inputtext").value;
  const key = cut16(document.getElementById("key").value);
  const encryptedText = aesecbenc(inputText, key);
  document.getElementById("encdec").textContent = encryptedText;
}

function decbtns() {
  const ciphertext = document.getElementById("inputtext").value;
  const key = cut16(document.getElementById("key").value);
  try {
    const decryptedText = aesecbdec(toByteArray(ciphertext), key);
    document.getElementById("encdec").textContent = decryptedText;
  } catch (e) {
    document.getElementById("encdec").textContent = "Decryption error: " + e.message;
  }
}

document.getElementById("encbtn")
  .addEventListener("click", encbtns, false);
document.getElementById("decbtn")
  .addEventListener("click", decbtns, false);

function copyOutput() {
  navigator.clipboard.writeText(
    document.getElementById("encdec").textContent
  )
  .then(() => alert("Copied to clipboard!"))
  .catch(err => console.error("Copy failed:", err));
}

document.getElementById("copyoutput")
  .addEventListener("click", copyOutput, false);
