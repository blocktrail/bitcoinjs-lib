var bitcoinjs = require('./src/index')
var bcrypto = require('./src/crypto')
var bscript = require('./src/script')
var assert = require('assert')

// spending P2WSH nested in P2SH
// /*

// vin1 witness:
// _
// 30440220121a629bb5fee3ecaf3e7a0b111101c51de816f427eaedd992b57f49b69b228e0220402ecd144a7321b4bad6ba3bfa5876b755b9c52a8c8ab17a33830d5929a76cbe01
// 512103b848ab6ac853cd69baaa750c70eb352ebeadb07da0ff5bbd642cb285895ee43f51ae
var keyPair = bitcoinjs.ECPair.fromWIF('QP3p9tRpTGTefG4a8jKoktSWC7Um8qzvt8wGKMxwWyW3KTNxMxN7', bitcoinjs.networks.segnet)
var pubKey = keyPair.getPublicKeyBuffer()
var pubKeyHash = bcrypto.hash160(pubKey)
var multisigScript = bscript.multisigOutput(1, [pubKey])
var segWitMultisigScript = bscript.segWitScriptHashOutput(bcrypto.sha256(multisigScript))
var p2sh = bscript.scriptHashOutput(bcrypto.hash160(segWitMultisigScript))

console.log(multisigScript)
console.log(bscript.decompile(multisigScript))
assert(multisigScript.toString('hex') === '512103b848ab6ac853cd69baaa750c70eb352ebeadb07da0ff5bbd642cb285895ee43f51ae')

console.log(bcrypto.sha256(multisigScript))
assert(bcrypto.sha256(multisigScript).toString('hex') === '86b2dcecbf2e0f0e4095ef11bc8834e2e148d245f844f0b8091389fef91b69ff')

console.log(segWitMultisigScript)
console.log(bscript.decompile(segWitMultisigScript))
assert(segWitMultisigScript.toString('hex') === '002086b2dcecbf2e0f0e4095ef11bc8834e2e148d245f844f0b8091389fef91b69ff')

console.log(p2sh)
console.log(bscript.decompile(p2sh))
assert(multisigScript.toString('hex') === '512103b848ab6ac853cd69baaa750c70eb352ebeadb07da0ff5bbd642cb285895ee43f51ae')

var txb = new bitcoinjs.TransactionBuilder(bitcoinjs.networks.segnet)

console.log('addInput')
txb.addInput('23d6640c3f3383ffc8233fbd830ee49162c720389bbba1c313a43b06a235ae13', 0, 4294967295) // 0.10000000 * 1e8

console.log('addOutput')
txb.addOutput("DMLasUfyFT5uxrbo2ETR1wtBBbYrNHCM65", parseInt(0.10000000 * 1e8))

console.log('sign')
console.log(txb.sign(0, keyPair, multisigScript, null, true, parseInt(0.10000000 * 1e8), segWitMultisigScript))

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

var shouldBeRaw = '0100000000010113ae35a2063ba413c3a1bb9b3820c76291e40e83bd3f23c8ff83333f0c64d623000000002322002086b2dcecbf2e0f0e4095ef11bc8834e2e148d245f844f0b8091389fef91b69ffffffffff0180969800000000001976a914b1ae3ceac136e4bdb733663e7a1e2f0961198a1788ac03004730440220121a629bb5fee3ecaf3e7a0b111101c51de816f427eaedd992b57f49b69b228e0220402ecd144a7321b4bad6ba3bfa5876b755b9c52a8c8ab17a33830d5929a76cbe0125512103b848ab6ac853cd69baaa750c70eb352ebeadb07da0ff5bbd642cb285895ee43f51ae00000000'
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
