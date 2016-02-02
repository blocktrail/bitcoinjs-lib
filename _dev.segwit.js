var bitcoinjs = require('./src/index')
var bcrypto = require('./src/crypto')
var bscript = require('./src/script')

// /*
// p2pkh DRXnpJKWNbPRwvA6w86rKSAUcoQTPPu6rm // p2sh(p2wpkh) MFDkRVPQgUU8ph6fqsihsnu2EPjHWjLKCz // p2wpkh ...
// QRtNLYQLpwLHn75LbHLRLo2U491ZPXt9AEbFyP3zbYrjftbrkgHX

var keyPair1 = bitcoinjs.ECPair.fromWIF('QWPDhFzyFuLkyqcCuQ7oQ5Ms5yxKrddtszpXTyzvpJcrFe4JwSQS', bitcoinjs.networks.segnet)
var keyPair2 = bitcoinjs.ECPair.fromWIF('QWPDhFzyFuLkyqcCuQ7oQ5Ms5yxKrddtszpXTyzvpJcrFe4JwSQS', bitcoinjs.networks.segnet)
var pubKey1 = keyPair1.getPublicKeyBuffer()
var pubKey2 = keyPair2.getPublicKeyBuffer()
var msigScript = bscript.multisigOutput(1, [pubKey1, pubKey2])
var msigScriptHash = bcrypto.hash256(msigScript)
var segWitScript = bscript.segWitScriptHashOutput(msigScriptHash)

console.log(msigScript.toString('hex'))
console.log(segWitScript.toString('hex'), segWitScript.length)

console.log(bscript.isSegWitScriptHashOutput(segWitScript))
console.log(bitcoinjs.address.fromOutputScript(segWitScript, bitcoinjs.networks.segnet))

console.log(bitcoinjs.address.toOutputScript("T7nZBtafiNv9ZhaZ7ujAFbTjzBPC6q9rk5KCdrFeAsy7Z6aDM1RPt", bitcoinjs.networks.segnet))

return

// console.log(bitcoinjs.address.toOutputScript('BQqmtkq4ph53rkTfp2SFtooYUH7jrQHz3J', bitcoinjs.networks.segnet))

//var prevOutScriptChunks = bscript.decompile(segWitScript)
//var prevOutType = bscript.classifyOutput(prevOutScriptChunks)
//console.log(prevOutType)
//console.log(prevOutScriptChunks)

var txb = new bitcoinjs.TransactionBuilder(bitcoinjs.networks.segnet)

console.log('addInput')
txb.addInput('e628ed878f8173db57a620f75ed28d0d17b5bb1d9e17986bd6fe3d12f891c7ba', 0, 4294967295) // 0.9997 * 1e8

console.log('addOutput')
txb.addOutput(bscript.scriptHashOutput(bcrypto.hash160(segWitScript)), parseInt(0.9996 * 1e8))

// console.log('incomplete', txb.buildIncomplete().toHex(true)) return

console.log('sign')
console.log(txb.sign(0, keyPair, segWitScript, null, true, parseInt(0.9997 * 1e8)))

var tx = txb.build()
var raw = tx.toHex(true)

var tx2 = bitcoinjs.Transaction.fromHex(raw)

console.log(' ===========\n === tx2 === ')
console.log('marker/flag', tx2.marker, tx2.flag)
tx2.ins[0].script = tx2.ins[0].script.toString('hex')
tx2.ins[0].witness = tx2.ins[0].witness.map(function(script) { return script.toString('hex') })
console.log('input', tx2.ins[0])
console.log('output', tx2.outs[0])
console.log('locktime', tx2.locktime)

var shouldBeRaw = '01000000000101bac791f8123dfed66b98179e1dbbb5170d8dd25ef720a657db73818f87ed28e60000000017160014dfad49bbc3318632df40093a7cc700dd1ea128acffffffff01c044f5050000000017a914504ce8a3d3035116bbf6c96f2528c786890b64c68702483045022100d1fa623748936a2e056465faf1112c1f61b3a5bf534add8e0ef2a80a5dbfeca4022050ed41d1f4eceaffd53947228de395b36f827fb4875345a1b99be97ec14324c0012103ae9ebf213eb699d4038acac7737df47baf754fd9cac42aff2b1a381f4a6529ce00000000'
console.log('r1', raw)
console.log('r2', shouldBeRaw)
console.log(raw === shouldBeRaw)
console.log(require('justdiff')(raw, shouldBeRaw))

var shouldBeTx = bitcoinjs.Transaction.fromHex(shouldBeRaw)

console.log(' ==================\n === shouldBeTx === ')
console.log('marker/flag', shouldBeTx.marker, shouldBeTx.flag)
shouldBeTx.ins[0].script = shouldBeTx.ins[0].script.toString('hex')
shouldBeTx.ins[0].witness = shouldBeTx.ins[0].witness.map(function(script) { return script.toString('hex') })
console.log('input', shouldBeTx.ins[0])
console.log('output', shouldBeTx.outs[0])
console.log('locktime', shouldBeTx.locktime)

// */
