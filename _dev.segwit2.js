var bitcoinjs = require('./src/index')
var bcrypto = require('./src/crypto')
var bscript = require('./src/script')

var pubKeyHash, segWitScript
// /*
// creating segwit version 0 output script (p2pkh)
pubKeyHash = new Buffer('751e76e8199196d454941c45d1b3a323f1433bd6', 'hex')

segWitScript = bscript.segWitPubKeyHashOutput(pubKeyHash)
var segWitRedeemScript = bscript.scriptHashOutput(bcrypto.hash160(segWitScript))
var segWitAddress = bitcoinjs.address.fromOutputScript(segWitRedeemScript, bitcoinjs.networks.segnet)
console.log(segWitAddress)

console.log(bscript.pubKeyHashOutput(pubKeyHash).toString('hex'))
console.log(bscript.segWitPubKeyHashOutput(pubKeyHash))

console.log(bitcoinjs.address.fromOutputScript(bscript.pubKeyHashOutput(pubKeyHash), bitcoinjs.networks.segnet))
console.log(bitcoinjs.address.fromOutputScript(bscript.segWitPubKeyHashOutput(pubKeyHash), bitcoinjs.networks.segnet))
console.log(bitcoinjs.address.toOutputScript('QWz9Bn74VCdsKLPDwapX23SBLCnKjBkEEQH5', bitcoinjs.networks.segnet))
// */

/*
// send to segwit version 0 (p2pkh) from plain p2pph
var txId = '874b7a996ddd5ef50065de11564ceafeb867540ee342e1fbfa1cc163448b0786'
var raw = '01000000019d89efe436044cfd50a458e6aff3c38f70f0f73f56f1ea2a72830077143f060b000000006b483045022100fe2bb049a9a25d855f869025ddec6c0b476c751f9e94fc70eba75682b9b057440220065896859d63c7165ccc9fa3f4423673bb49a9594e36507cac726079eb37fa2f0121039411656e6630f83cd89063886f2252e8056d78c67641e8c0a75bf4e0fafabebffeffffff022002164e020000001976a9147657022345ee0cd73a2c36ec0ee90976ea8880e688ac00e1f5050000000017a9143ed18b077bb3a117f17fd623e0f335613cfbc182877e050000'
var tx = bitcoinjs.Transaction.fromHex(raw)

console.log(bscript.classifyInput(tx.ins[0].script))
console.log(tx.witness)
// */

/*
// spending segwit version 0 (p2pkh)
var txId = 'aeed4630a552595d39159e91ecd80f1e99a2d0bf6f7206fbe95cdcca6a25619a'
var raw = '01000000000101a75226c4fc4bb72e705d85447f7110fcd090d97978f4171b57a68c1b0c38225d000000001c1b001976a914dfad49bbc3318632df40093a7cc700dd1ea128ac88acfeffffff02404b4c000000000017a914ca20fed95da85d64e8831924f5f84dc69ba2228e87934a4c00000000001976a91484fe4676a3651eb271f3c36cc6c3cee1df838f9b88ac02483045022100927511daf2aff4aab356014bd297bc16961f3ed14c2b36b5d46bd9460d2ba52e02205ad7daf76c69b4db55b30453b8a15b4f7f7a3e34ed98aca6ca77383007af7c8b012103ae9ebf213eb699d4038acac7737df47baf754fd9cac42aff2b1a381f4a6529ce9f010000'
var tx = bitcoinjs.Transaction.fromHex(raw)

console.log(bscript.classifyInput(tx.ins[0].script))

console.log(tx.ins[0])

var signature = tx.ins[0].witness[0]
var pubKey = tx.ins[0].witness[1]
var pubKeyHash = bcrypto.hash160(pubKey)
console.log(pubKey)
console.log(pubKeyHash)

console.log(new Buffer('7d99e1d990db6f8812da82510e01a55950aeed39', 'hex'))
console.log(bscript.pubKeyHashOutput(pubKeyHash))
console.log(bscript.segWitPubKeyHashOutput(pubKeyHash))

var newRaw = tx.toHex(true)
console.log('r1', raw)
console.log('r2', newRaw)
console.log(raw == newRaw)
// */

/*
// p2pkh DRXnpJKWNbPRwvA6w86rKSAUcoQTPPu6rm // p2sh(p2wpkh) MFDkRVPQgUU8ph6fqsihsnu2EPjHWjLKCz // p2wpkh ...
// QRtNLYQLpwLHn75LbHLRLo2U491ZPXt9AEbFyP3zbYrjftbrkgHX

var keyPair = bitcoinjs.ECPair.fromWIF('QWPDhFzyFuLkyqcCuQ7oQ5Ms5yxKrddtszpXTyzvpJcrFe4JwSQS', bitcoinjs.networks.segnet)
var pubKey = keyPair.getPublicKeyBuffer()
var pubKeyHash = bcrypto.hash160(pubKey)
var segWitScript = bscript.segWitPubKeyHashOutput(pubKeyHash)

console.log(bscript.pubKeyHashOutput(pubKeyHash).toString('hex'))
console.log(segWitScript.toString('hex'))
console.log(bitcoinjs.address.fromOutputScript(bscript.pubKeyHashOutput(pubKeyHash), bitcoinjs.networks.segnet))
console.log(bitcoinjs.address.fromOutputScript(bscript.scriptHashOutput(bcrypto.hash160(segWitScript)), bitcoinjs.networks.segnet))
console.log(bitcoinjs.address.fromOutputScript(segWitScript, bitcoinjs.networks.segnet))

// console.log(bitcoinjs.address.toOutputScript('BQqmtkq4ph53rkTfp2SFtooYUH7jrQHz3J', bitcoinjs.networks.segnet))

//var prevOutScriptChunks = bscript.decompile(segWitScript)
//var prevOutType = bscript.classifyOutput(prevOutScriptChunks)
//console.log(prevOutType)
//console.log(prevOutScriptChunks)

var txb = new bitcoinjs.TransactionBuilder(bitcoinjs.networks.segnet)

console.log('addInput')
txb.addInput('fe7fc41334fac4fb0b0e17c2781d12dc0d9dfb1e96557155cee7d5588fa8affa', 0, 4294967295) // 0.9998 * 1e8

console.log('addOutput')
txb.addOutput(segWitScript, parseInt(0.9997 * 1e8, 10))

// console.log('incomplete', txb.buildIncomplete().toHex(true)) return

console.log('sign')
console.log(txb.sign(0, keyPair, null, null, true, parseInt(0.9998 * 1e8)))

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

var shouldBeRaw = '010000000001019df55762a6ea295530723059620691c4e0280ac7d18d07076f3d4f492799536a0000000000ffffffff01e092f50500000000160014dfad49bbc3318632df40093a7cc700dd1ea128ac02483045022100d92c261ff35b98ea2858a54835b699616f2b3d301f8a66962a67ccb8b5a8624b0220348225df776e4801172016093740648c9deec42ea8914949c3ca32d987463ea2012103ae9ebf213eb699d4038acac7737df47baf754fd9cac42aff2b1a381f4a6529ce00000000'
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

/*
// p2pkh DRXnpJKWNbPRwvA6w86rKSAUcoQTPPu6rm // p2sh(p2wpkh) MFDkRVPQgUU8ph6fqsihsnu2EPjHWjLKCz // p2wpkh ...
// QRtNLYQLpwLHn75LbHLRLo2U491ZPXt9AEbFyP3zbYrjftbrkgHX

var keyPair = bitcoinjs.ECPair.fromWIF('QWPDhFzyFuLkyqcCuQ7oQ5Ms5yxKrddtszpXTyzvpJcrFe4JwSQS', bitcoinjs.networks.segnet)
var pubKey = keyPair.getPublicKeyBuffer()
var pubKeyHash = bcrypto.hash160(pubKey)
var segWitScript = bscript.segWitPubKeyHashOutput(pubKeyHash)

console.log(bscript.pubKeyHashOutput(pubKeyHash).toString('hex'))
console.log(segWitScript.toString('hex'))
console.log(bitcoinjs.address.fromOutputScript(bscript.pubKeyHashOutput(pubKeyHash), bitcoinjs.networks.segnet))
console.log(bitcoinjs.address.fromOutputScript(bscript.scriptHashOutput(bcrypto.hash160(segWitScript)), bitcoinjs.networks.segnet))
console.log(bitcoinjs.address.fromOutputScript(segWitScript, bitcoinjs.networks.segnet))

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

// /*
// example from; https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
var keyPair1 = bitcoinjs.ECPair.fromWIF('QUucBMCfGcqe5WkJ99KyzcUnzerarVAqCgJXDM6dBqPX9ESYi13K', bitcoinjs.networks.segnet)
var keyPair2 = bitcoinjs.ECPair.fromWIF('QRtNLYQLpwLHn75LbHLRLo2U491ZPXt9AEbFyP3zbYrjftbrkgHX', bitcoinjs.networks.segnet)

// console.log((new bitcoinjs.ECPair(keyPair1.d, null)).toWIF())
// console.log((new bitcoinjs.ECPair(keyPair2.d, null)).toWIF())

var pubKey = keyPair2.getPublicKeyBuffer()
pubKeyHash = bcrypto.hash160(pubKey)
segWitScript = bscript.segWitPubKeyHashOutput(pubKeyHash)

console.log(bscript.pubKeyHashOutput(pubKeyHash).toString('hex'))

var txb = new bitcoinjs.TransactionBuilder(bitcoinjs.networks.segnet)

console.log('addInput')
txb.addInput('9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff', 0, 4294967278, new Buffer('2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac', 'hex')) // 6.25 * 1e8
txb.addInput('8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef', 1, 4294967295) // 6.0 * 1e8

console.log('addOutput')
txb.addOutput('DH38ZWSZ7u6xpkXx9td6rfrZpvkU9ssuJf', parseInt(1.1234 * 1e8, 10))
txb.addOutput('DAbefZ33P8TbiWubFaEj6Z2UTwgNsksfKf', parseInt(2.2345 * 1e8, 10))

txb.tx.locktime = 17

console.log('sign')

// sign input1; pubkey
console.log(txb.sign(0, keyPair1, null, null, false, parseInt(6.26 * 1e8, 10)))

// sign input2; p2wpkh
console.log(txb.sign(1, keyPair2, null, null, true, parseInt(6.0 * 1e8, 10)))

console.log('build')
var tx = txb.build()

console.log('toHex')
var raw = tx.toHex(true)

console.log('fromHex')
var tx2 = bitcoinjs.Transaction.fromHex(raw)

console.log(tx2)

console.log(' ===========\n === tx2 === ')
console.log('marker/flag', tx2.marker, tx2.flag)

tx2.ins[0].script = tx2.ins[0].script.toString('hex')
tx2.ins[1].script = tx2.ins[1].script.toString('hex')
tx2.ins[1].witness = tx2.ins[1].witness.map(function (script) { return script.toString('hex') })
console.log('input1', tx2.ins[0])
console.log('input2', tx2.ins[1])

var shouldBeRaw = '01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000'
console.log('r1', raw)
console.log('r2', shouldBeRaw)
console.log(raw === shouldBeRaw)
console.log(require('justdiff')(raw, shouldBeRaw))

var shouldBeTx = bitcoinjs.Transaction.fromHex(shouldBeRaw)

console.log(' ==================\n === shouldBeTx === ')
console.log('marker/flag', shouldBeTx.marker, shouldBeTx.flag)
shouldBeTx.ins[0].script = shouldBeTx.ins[0].script.toString('hex')
shouldBeTx.ins[1].script = shouldBeTx.ins[1].script.toString('hex')
shouldBeTx.ins[1].witness = shouldBeTx.ins[1].witness.map(function (script) { return script.toString('hex') })
console.log('input1', shouldBeTx.ins[0])
console.log('input2', shouldBeTx.ins[1])
// */
