#!/usr/bin/env node
'use strict';

var program = require('commander');
var fs = require('fs');
var bitcore = require('bitcore-lib');
var Message = require('./message');
var JSONStream = require('jsonstream');
var Signature = bitcore.crypto.Signature;

program
  .usage('<addresses-file> <message-file>')
  .description('Verify ownership of addresses')
  .parse(process.argv);

if(program.args.length !== 2) {
  return program.help();
}

var addressesFile = program.args[0];
var messageFile = program.args[1];
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

  var network = new bitcore.Address(data.address).network;
  var script = bitcore.Script.buildMultisigOut(data.publicKeys, data.threshold);
  var checkAddress = script.toScriptHashOut().toAddress(network).toString();

  if(checkAddress !== data.address) {
    console.error('Address Mismatch! ' + data.address + ' != ' + checkAddress);
    failCount++;
    return;
  }

  var validSignatures = 0;

  for(var i = 0; i < data.publicKeys.length; i++) {
    var pubKey = data.publicKeys[i];
    if(data.signatures[pubKey]) {
      var signature = Signature.fromCompact(new Buffer(data.signatures[pubKey], 'base64'));
      var verified = Message(message)._verify(new bitcore.PublicKey(pubKey), signature);
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