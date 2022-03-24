#!/usr/bin/env node
'use strict';

var program = require('commander');
var fs = require('fs');
var Client = require('bitcore-wallet-client').default;
var Message = require('./message');
var sjcl = require('sjcl');
var ttyread = require('ttyread');
const CWC = require('crypto-wallet-core');

const bitcoreLibs = {
  BTC: CWC.BitcoreLib,
  DOGE: CWC.BitcoreLibDoge,
  LTC: CWC.BitcoreLibLtc,
  BCH: CWC.BitcoreLibCash
};

var BWS_INSTANCE_URL = 'https://bws.bitpay.com/bws/api';

program
  .usage('<wallet-file> <message-file> <output-file> <currency>')
  .description('Sign a message with copay private keys')
  .parse(process.argv);

if(program.args.length !== 4) {
  return program.help();
}

var walletFile = program.args[0];
var messageFile = program.args[1];
var outputFile = program.args[2];
const currency = program.args[3];

var message = fs.readFileSync(messageFile, 'utf8');
var encryptedString = fs.readFileSync(walletFile, 'utf8');
var outStream = fs.createWriteStream(outputFile);

var decryptedString;
var walletMetadata;
var network;
var networkDerivation;
var threshold;
var path;
var hdPrivateKey;
var clientXPubKeys;
var copayerIndex;

var count = 0;

ttyread('Password: ', {silent: true}, function(err, password) {
  if(err) {
    console.log(err);
    return;
  }

  try {
    decryptedString = sjcl.decrypt(password, encryptedString);
  } catch(e) {
    if(e.message === 'ccm: tag doesn\'t match') {
      console.error('Incorrect Password');
    } else {
      console.error(e.message);
    }

    return;
  }

  walletMetadata = JSON.parse(decryptedString);
  const legacyCoPay = !Boolean(walletMetadata.credentials);

  if(legacyCoPay && ['BIP44', 'BIP45'].indexOf(walletMetadata.derivationStrategy) === -1) {
    throw new Error('Derivation strategy is not BIP44 or BIP45 (' + walletMetadata.derivationStrategy + ')');
  }

  if(!walletMetadata.compliantDerivation) {
    console.error('WARNING: compliantDerivation = false');
  }

  network = walletMetadata.network;
  networkDerivation = network === 'testnet' ? '1' : '0';
  threshold = walletMetadata.m;

  let path;
  if (legacyCoPay) {
    if(walletMetadata.derivationStrategy === 'BIP44') {
      path = "m/44'/" + networkDerivation + "'/" + walletMetadata.account + "'";
    } else if(walletMetadata.derivationStrategy === 'BIP45') {
      path = "m/45'";
    }
  } else {
    path = walletMetadata.credentials.rootPath;
  }

  const privKey = legacyCoPay ? walletMetadata.xPrivKey : walletMetadata.key.xPrivKey;
  hdPrivateKey = new bitcoreLibs[currency].HDPrivateKey(privKey).deriveChild(path);

  const pubKeyRing = legacyCoPay ? walletMetadata.publicKeyRing : walletMetadata.credentials.publicKeyRing;
  clientXPubKeys = pubKeyRing.map(function(ring) {
    return new bitcoreLibs[currency].HDPublicKey(ring.xPubKey);
  });

  var client = new Client({
    baseUrl: BWS_INSTANCE_URL,
    verbose: true
  });

  if (legacyCoPay) {
    walletMetadata.version = 2;
    client.fromObj(walletMetadata);
  } else {
    client.fromObj(walletMetadata.credentials);
  }

  client.getStatus({includeExtendedInfo: true}, function(err, status) {
    if(err) {
      console.error(err);
      return;
    }

    copayerIndex = status.wallet.addressManager.copayerIndex;

    if(walletMetadata.derivationStrategy === 'BIP45' && !copayerIndex) {
      throw new Error('Missing copayerIndex');
    }

    var receiveAddressIndex = status.wallet.addressManager.receiveAddressIndex;
    var changeAddressIndex = status.wallet.addressManager.changeAddressIndex;

    console.log('receiveAddressIndex', receiveAddressIndex);
    console.log('changeAddressIndex', changeAddressIndex);

    var indexPrefix = "m/";

    if(walletMetadata.derivationStrategy === 'BIP45') {
      indexPrefix += copayerIndex + '/';
    }

    outStream.write('[\n');

    // Derive main addresses
    for(var i = 0; i < receiveAddressIndex - 1; i++) {
      processAddress(indexPrefix + '0/' + i, false);
    }

    if(receiveAddressIndex && changeAddressIndex) {
      processAddress(indexPrefix + '0/' + (receiveAddressIndex - 1), false);
    } else if(receiveAddressIndex) {
      processAddress(indexPrefix + '0/' + (receiveAddressIndex - 1), true);
    }

    // Derive change addresses
    for(var i = 0; i < changeAddressIndex - 1; i++) {
      processAddress(indexPrefix + '1/' + i, false);
    }

    if(changeAddressIndex) {
      processAddress(indexPrefix + '1/' + (changeAddressIndex - 1), true);
    }

    outStream.write(']\n');
  });
});


function processAddress(path, last) {
  if(count % 10 === 0) {
    console.log(count);
  }

  var priv = hdPrivateKey.deriveChild(path).privateKey;
  var pub = priv.publicKey;

  var publicKeys = clientXPubKeys.map(function(xPubKey) {
    return xPubKey.derive(path).publicKey.toString();
  });
  console.log(publicKeys, pub.toString())
  if(publicKeys.indexOf(pub.toString()) === -1) {
    throw new Error('Public key mismatch: ' + pub.toString());
  }

  const m = walletMetadata.m || walletMetadata.credentials.m;
  var script = bitcoreLibs[currency].Script.buildMultisigOut(publicKeys, m);
  var address = script.toScriptHashOut().toAddress(bitcoreLibs[currency].Networks.get(network)).toString();

  var signature = Message(message, currency).sign(priv);

  var obj = {
    address: address,
    threshold: m,
    path: path,
    publicKeys: publicKeys,
    signatures: {}
  };

  obj.signatures[pub.toString()] = signature;

  outStream.write(JSON.stringify(obj, null, 2));

  if(!last) {
    outStream.write(',');
  }

  outStream.write('\n');
  count++;
}
