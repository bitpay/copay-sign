Copay Sign
=============

These utilities allow you to prove control over a Copay multisignature wallet.

## Installation

Run `npm install`.

## Sign message with private keys

`node sign.js <wallet-file> <message-file> <output-file>`

If you have a two of three wallet, this needs to be done for two of the three copayers.

You can get a wallet file by clicking Settings -> Your Wallet -> More Options -> Export Wallet.

## Combine signatures into one file

`node combine.js <file-1> <file-2> <output-file>`

## Verify signatures

`node verify.js <address-file> <message-file>`

This iterates through each address and checks that there are sufficient valid signatures.