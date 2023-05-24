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
  // Convert text to bytes
  //var text = 'TextMustBe16Byte';
  var textBytes = encoder.encode(text);

  var aesEcb = new ECB(key);
  var encryptedBytes = new Uint8Array(textBytes.length);
  aesEcb.encrypt(textBytes, encryptedBytes);
  return fromByteArray(encryptedBytes);
}

function aesecbdec(encryptedBytes, key) {
  var aesEcb = new ECB(key);
  var decryptedBytes = new Uint8Array(encryptedBytes.length);
  aesEcb.decrypt(encryptedBytes, decryptedBytes);

  // Convert our bytes back into text
  var decryptedText = decoder.decode(decryptedBytes);
  return decryptedText;
}

function longtext(text) {
  var chunksize = 6;
  var texts =
    text.match(/[\s\S]{1,16}/g) || [' '];
  texts.push(texts.pop().padEnd(16));
  return texts;
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
  var text = longtext(document
    .getElementById("inputtext").value);
  var key = cut16(document
    .getElementById("key").value);
  var endo = "";
  for (var i = 0; i < text.length; i++) {
    endo = endo + aesecbenc(text[i], key) + '@';
  }
  document.getElementById("encdec")
    .innerHTML = endo;
}

document.getElementById("encbtn")
  .addEventListener("click", encbtns, false);

function cutter(text) {
  var texts = [];
  var chunk = '';
  for (var i = 0; i < text.length; i++) {
    if (text[i] == '@') {
      texts.push(chunk);
      chunk = '';
    }
    else {
      chunk = chunk + text[i];
    }
  }
  if (chunk) { texts.push(chunk); } //last @
  return texts;
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
    document.getElementById("encdec").value)
}

document.getElementById("copyoutput")
  .addEventListener("click", copyOutput, false);