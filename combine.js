#!/usr/bin/env node
'use strict';

var program = require('commander');
var fs = require('fs');
var JSONStream = require('jsonstream');

var BWS_INSTANCE_URL = 'https://bws.bitpay.com/bws/api';

program
  .usage('<first-address-file> <second-address-file> <output-file>')
  .description('Merge signatures from two files into one')
  .parse(process.argv);

if(program.args.length !== 3) {
  return program.help();
}

var file1 = program.args[0];
var file2 = program.args[1];
var outputFile = program.args[2];
var outStream = fs.createWriteStream(outputFile, 'utf8');

// Load second file signatures into memory

var signatures = {};

var inStream2 = fs.createReadStream(file2, 'utf8');
var jsonStream2 = JSONStream.parse('*');

jsonStream2.on('data', function(data) {
  signatures[data.address] = {};
  for(var key in data.signatures) {
    signatures[data.address][key] = data.signatures[key];
  }
});

jsonStream2.on('end', function() {
  // Load first file, add signatures and output
  var inStream1 = fs.createReadStream(file1, 'utf8');
  var jsonStream1 = JSONStream.parse('*');

  outStream.write('[\n');
  var first = true;

  jsonStream1.on('data', function(data) {
    if(!signatures[data.address]) {
      console.error('Warning: ' + data.address + ' missing from ' + file2);
      return;
    }

    if(!first) {
      outStream.write(',\n');
    } else {
      first = false;
    }

    for(var key in signatures[data.address]) {
      data.signatures[key] = signatures[data.address][key];
    }

    outStream.write(JSON.stringify(data, null, 2))
  });

  jsonStream1.on('end', function() {
    outStream.write('\n]\n');
  });

  inStream1.pipe(jsonStream1);
});

inStream2.pipe(jsonStream2);