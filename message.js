'use strict';

// Copied from https://github.com/bitpay/bitcore-message/blob/master/lib/message.js
// Due to multiple bitcore version issues
const CWC = require('crypto-wallet-core');

const bitcoreLibs = {
  BTC: CWC.BitcoreLib,
  DOGE: CWC.BitcoreLibDoge,
  LTC: CWC.BitcoreLibLtc,
  BCH: CWC.BitcoreLibCash
};

/**
 * constructs a new message to sign and verify.
 *
 * @param {String} message
 * @returns {Message}
 */
var Message = function Message(message, currency) {
  if (!(this instanceof Message)) {
    return new Message(message);
  }
  this.$ = this.bitcore.util.preconditions;
  this.$.checkArgument(_.isString(message), 'First argument should be a string');
  this.message = message;
  this.bitcore = bitcoreLibs[currency];
  this.PrivateKey = this.bitcore.PrivateKey;
  this.PublicKey = this.bitcore.PublicKey;
  this.Address = this.bitcore.Address;
  this.BufferWriter = this.bitcore.encoding.BufferWriter;
  this.ECDSA = this.bitcore.crypto.ECDSA;
  this.Signature = this.bitcore.Signature;
  this.sha256sha256 = this.bitcore.crypto.Hash.sha256sha256;
  this.JSUtil = this.bitcore.util.js;
  this._ = this.bitcore.deps._;

  return this;
};

Message.MAGIC_BYTES = new Buffer('Bitcoin Signed Message:\n');

Message.prototype.magicHash = function magicHash() {
  var prefix1 = this.BufferWriter.varintBufNum(Message.MAGIC_BYTES.length);
  var messageBuffer = new Buffer(this.message);
  var prefix2 = this.BufferWriter.varintBufNum(messageBuffer.length);
  var buf = Buffer.concat([prefix1, Message.MAGIC_BYTES, prefix2, messageBuffer]);
  var hash = this.sha256sha256(buf);
  return hash;
};

Message.prototype._sign = function _sign(privateKey) {
  $.checkArgument(privateKey instanceof this.PrivateKey,
    'First argument should be an instance of PrivateKey');
  var hash = this.magicHash();
  var ecdsa = new this.ECDSA();
  ecdsa.hashbuf = hash;
  ecdsa.privkey = privateKey;
  ecdsa.pubkey = privateKey.toPublicKey();
  ecdsa.signRandomK();
  ecdsa.calci();
  return ecdsa.sig;
};

/**
 * Will sign a message with a given bitcoin private key.
 *
 * @param {PrivateKey} privateKey - An instance of PrivateKey
 * @returns {String} A base64 encoded compact signature
 */
Message.prototype.sign = function sign(privateKey) {
  var signature = this._sign(privateKey);
  return signature.toCompact().toString('base64');
};

Message.prototype._verify = function _verify(publicKey, signature) {
  $.checkArgument(publicKey instanceof this.PublicKey, 'First argument should be an instance of PublicKey');
  $.checkArgument(signature instanceof this.Signature, 'Second argument should be an instance of Signature');
  var hash = this.magicHash();
  var verified = this.ECDSA.verify(hash, signature, publicKey);
  if (!verified) {
    this.error = 'The signature was invalid';
  }
  return verified;
};

/**
 * Will return a boolean of the signature is valid for a given bitcoin address.
 * If it isn't the specific reason is accessible via the "error" member.
 *
 * @param {Address|String} bitcoinAddress - A bitcoin address
 * @param {String} signatureString - A base64 encoded compact signature
 * @returns {Boolean}
 */
Message.prototype.verify = function verify(bitcoinAddress, signatureString) {
  $.checkArgument(bitcoinAddress);
  $.checkArgument(signatureString && this._.isString(signatureString));

  if (this._.isString(bitcoinAddress)) {
    bitcoinAddress = this.Address.fromString(bitcoinAddress);
  }
  var signature = this.Signature.fromCompact(new Buffer(signatureString, 'base64'));

  // recover the public key
  var ecdsa = new this.ECDSA();
  ecdsa.hashbuf = this.magicHash();
  ecdsa.sig = signature;
  var publicKey = ecdsa.toPublicKey();

  var signatureAddress = this.Address.fromPublicKey(publicKey, bitcoinAddress.network);

  // check that the recovered address and specified address match
  if (bitcoinAddress.toString() !== signatureAddress.toString()) {
    this.error = 'The signature did not match the message digest';
    return false;
  }

  return this._verify(publicKey, signature);
};

/**
 * Instantiate a message from a message string
 *
 * @param {String} str - A string of the message
 * @returns {Message} A new instance of a Message
 */
Message.fromString = function(str) {
  return new Message(str);
};

/**
 * Instantiate a message from JSON
 *
 * @param {String} json - An JSON string or Object with keys: message
 * @returns {Message} A new instance of a Message
 */
Message.fromJSON = function fromJSON(json) {
  if (this.JSUtil.isValidJSON(json)) {
    json = JSON.parse(json);
  }
  return new Message(json.message);
};

/**
 * @returns {Object} A plain object with the message information
 */
Message.prototype.toObject = function toObject() {
  return {
    message: this.message
  };
};

/**
 * @returns {String} A JSON representation of the message information
 */
Message.prototype.toJSON = function toJSON() {
  return JSON.stringify(this.toObject());
};

/**
 * Will return a the string representation of the message
 *
 * @returns {String} Message
 */
Message.prototype.toString = function() {
  return this.message;
};

/**
 * Will return a string formatted for the console
 *
 * @returns {String} Message
 */
Message.prototype.inspect = function() {
  return '<Message: ' + this.toString() + '>';
};

module.exports = Message;