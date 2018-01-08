var Buffer = require('safe-buffer').Buffer
var bech32 = require('bech32')
var cashaddress = require('cashaddress')
var bs58check = require('bs58check')
var bscript = require('./script')
var btemplates = require('./templates')
var networks = require('./networks')
var typeforce = require('typeforce')
var types = require('./types')

function fromBase58Check (address) {
  var payload = bs58check.decode(address)

  // TODO: 4.0.0, move to 'toOutputScript'
  if (payload.length < 21) throw new TypeError(address + ' is too short')
  if (payload.length > 21) throw new TypeError(address + ' is too long')

  var version = payload.readUInt8(0)
  var hash = payload.slice(1)

  return { version: version, hash: hash }
}

function fromBech32 (address) {
  var result = bech32.decode(address)
  var data = bech32.fromWords(result.words.slice(1))

  return {
    version: result.words[0],
    prefix: result.prefix,
    data: Buffer.from(data)
  }
}

function fromCashAddress (address) {
  return cashaddress.decode(address)
}

function toBase58Check (hash, version) {
  typeforce(types.tuple(types.Hash160bit, types.UInt8), arguments)

  var payload = Buffer.allocUnsafe(21)
  payload.writeUInt8(version, 0)
  hash.copy(payload, 1)

  return bs58check.encode(payload)
}

function toBech32 (data, version, prefix) {
  var words = bech32.toWords(data)
  words.unshift(version)

  return bech32.encode(prefix, words)
}

function toCashAddress (data, scriptType, prefix) {
  return cashaddress.encode(prefix, scriptType, data)
}

function fromOutputScript (outputScript, network, useNewCashAddress) {
  network = network || networks.bitcoin
  useNewCashAddress = useNewCashAddress || false

  if ('cashAddrPrefix' in network && useNewCashAddress) {
    if (bscript.pubKeyHash.output.check(outputScript)) return toCashAddress(bscript.compile(outputScript).slice(3, 23), btemplates.types.P2PKH, network.cashAddrPrefix)
    if (bscript.scriptHash.output.check(outputScript)) return toCashAddress(bscript.compile(outputScript).slice(2, 22), btemplates.types.P2SH, network.cashAddrPrefix)
  } else {
    if (bscript.pubKeyHash.output.check(outputScript)) return toBase58Check(bscript.compile(outputScript).slice(3, 23), network.pubKeyHash)
    if (bscript.scriptHash.output.check(outputScript)) return toBase58Check(bscript.compile(outputScript).slice(2, 22), network.scriptHash)
  }

  if (bscript.witnessPubKeyHash.output.check(outputScript)) return toBech32(bscript.compile(outputScript).slice(2, 22), 0, network.bech32)
  if (bscript.witnessScriptHash.output.check(outputScript)) return toBech32(bscript.compile(outputScript).slice(2, 34), 0, network.bech32)

  throw new Error(bscript.toASM(outputScript) + ' has no matching Address')
}

function toOutputScript (address, network, useNewCashAddress) {
  network = network || networks.bitcoin

  var decode
  if ('cashAddrPrefix' in network && useNewCashAddress) {
    try {
      decode = fromCashAddress(address)
      if (decode.version === 'pubkeyhash') return bscript.pubKeyHash.output.encode(decode.hash)
      if (decode.version === 'scripthash') return bscript.scriptHash.output.encode(decode.hash)
    } catch (e) {

    }

    if (decode) {
      if (decode.prefix !== network.cashAddrPrefix) throw new Error(address + ' has an invalid prefix')
    }
  }

  try {
    decode = fromBase58Check(address)
    if (decode.version === network.pubKeyHash) return bscript.pubKeyHash.output.encode(decode.hash)
    if (decode.version === network.scriptHash) return bscript.scriptHash.output.encode(decode.hash)
  } catch (e) {}

  if (!decode && 'bech32' in network) {
    try {
      decode = fromBech32(address)
    } catch (e) {}

    if (decode) {
      if (decode.prefix !== network.bech32) throw new Error(address + ' has an invalid prefix')
      if (decode.version === 0) {
        if (decode.data.length === 20) return bscript.witnessPubKeyHash.output.encode(decode.data)
        if (decode.data.length === 32) return bscript.witnessScriptHash.output.encode(decode.data)
      }
    }
  }

  throw new Error(address + ' has no matching Script')
}

module.exports = {
  fromBase58Check: fromBase58Check,
  fromBech32: fromBech32,
  fromCashAddress: fromCashAddress,
  fromOutputScript: fromOutputScript,
  toBase58Check: toBase58Check,
  toBech32: toBech32,
  toCashAddress: toCashAddress,
  toOutputScript: toOutputScript
}
