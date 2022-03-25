#!/usr/bin/env node
'use strict';

var program = require('commander');
var fs = require('fs');
const CWC = require('crypto-wallet-core');
var JSONStream = require('jsonstream');
const bitcoreLibs = {
  BTC: CWC.BitcoreLib,
  DOGE: CWC.BitcoreLibDoge,
  LTC: CWC.BitcoreLibLtc,
  BCH: CWC.BitcoreLibCash
};

program
  .usage('<addresses-file> <message-file> <currency> <bech32>')
  .description('Verify ownership of addresses')
  .parse(process.argv);

if(program.args.length !== 3 && program.args.length !== 4) {
  return program.help();
}

var addressesFile = program.args[0];
var messageFile = program.args[1];
const currency = program.args[2];
const bech32 = program.args[3];
var message = fs.readFileSync(messageFile, 'utf8');

var inStream = fs.createReadStream(addressesFile, 'utf8');
var jsonStream = JSONStream.parse('*');

var addressCount = 0;
var successCount = 0;
var failCount = 0;

jsonStream.on('data', function(data) {
  addressCount++;
  if(addressCount % 10 === 0) {
    console.log(addressCount);
  }

  var network = new bitcoreLibs[currency].Address(data.address).network;
  let nestedWitness;
  let type;
  if (bech32) {
    nestedWitness = false;
    type = 'witnessscripthash';
  }
  let checkAddress = bitcoreLibs[currency].Address.createMultisig(data.publicKeys, data.threshold, network, nestedWitness, type);
  checkAddress = checkAddress.toString();
  if(checkAddress !== data.address) {
    console.error('Address Mismatch! ' + data.address + ' != ' + checkAddress);
    failCount++;
    return;
  }

  var validSignatures = 0;

  for(var i = 0; i < data.publicKeys.length; i++) {
    var pubKey = data.publicKeys[i];
    if(data.signatures[pubKey]) {
      var signature = bitcoreLibs.BTC.crypto.Signature.fromCompact(new Buffer(data.signatures[pubKey], 'base64'));
      var verified = bitcoreLibs.BTC.Message(message)._verify(new bitcoreLibs.BTC.PublicKey(pubKey), signature);
      if(verified) {
        validSignatures++;
      } else {
        console.error('Signature check failed for ' + data.address + '!');
      }
    }
  }
  if(validSignatures < data.threshold) {
    console.error('Not enough valid signatures for ' + data.address + '!');
    failCount++;
    return;
  }

  successCount++;
});

jsonStream.on('end', function() {
  console.log('Processed ' + addressCount + ' addresses');
  console.log('Success count: ' + successCount);
  console.log('Fail count: ' + failCount);
});

inStream.pipe(jsonStream);
