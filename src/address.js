var Buffer = require('safe-buffer').Buffer
var bech32 = require('bech32')
var base32 = require('cashaddress')
var bs58check = require('bs58check')
var bscript = require('./script')
var btemplates = require('./templates')
var networks = require('./networks')
var typeforce = require('typeforce')
var types = require('./types')

function getHashBitSizeFlags (size) {
  if (size % 32 !== 0) {
    throw new Error('Invalid length for hash - must be an even multiple of 32 bits')
  }
  if (size < 160 || size > 512) {
    throw new Error('Length of hash is out of range [160 >= x <= 512]')
  }
  switch (size) {
    case 160: return 0
    case 192: return 1
    case 224: return 2
    case 256: return 3
    case 320: return 4
    case 384: return 5
    case 448: return 6
    case 512: return 7
  }
}

function getScriptTypeFlags (type) {
  switch (type) {
    case btemplates.types.P2PKH: return 0
    case btemplates.types.P2SH: return 1
    default: throw new Error('Invalid script type')
  }
}

function parseBase32Version (version) {
  // 1 bit  (8  ):   MSB: 0 (reserved)
  // 4 bits (3-7):   script type
  // 3 bits (0-2):   LSB: hash size
  if ((version >> 7) & 1) {
    throw new Error('Invalid version, MSB is reserved');
  }
  var scriptType
  switch ((version >> 3) & 0xf) {
    case 0:
      scriptType = btemplates.types.P2PKH
      break
    case 1:
      scriptType = btemplates.types.P2SH
      break
    default:
      throw new Error('Invalid script type')
  }

  var hashBits = version & 0x07
  var hashLengthBits
  switch (hashBits) {
    case 0: hashLengthBits = 160; break
    case 1: hashLengthBits = 192; break
    case 2 : hashLengthBits = 224; break
    case 3 : hashLengthBits = 256; break
    case 4 : hashLengthBits = 320; break
    case 5 : hashLengthBits = 384; break
    case 6 : hashLengthBits = 448; break
    case 7 : hashLengthBits = 512; break
    default:
      throw new Error('Invalid bits for hash');
  }

  return {
    scriptType: scriptType,
    hashSize: hashLengthBits
  }
}

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

function fromBase32 (address) {
  var result = base32.decode(address)
  var data = base32.fromWords(result.words)
  var version = data[0]
  var versionInfo = parseBase32Version(version)
  if (1 + (versionInfo.hashSize / 8) !== data.length) {
    throw new Error('Incorrect data size for this address version')
  }
  return {
    version: versionInfo.scriptType,
    prefix: result.prefix,
    hash: Buffer.from(data.slice(1))
  }
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

function getAddressVersion (hash, type) {
  var hashFlags = getHashBitSizeFlags(hash.length * 8)
  var script = getScriptTypeFlags(type)
  return script << 3 | hashFlags
}

function toBase32 (data, scriptType, prefix) {
  var addrVer = getAddressVersion(data, scriptType)
  var payload = Buffer.allocUnsafe(1 + data.length)
  payload.writeUInt8(addrVer, 0)
  data.copy(payload, 1)
  var words = base32.toWords(payload)
  return base32.encode(prefix, words)
}

function fromOutputScript (outputScript, network, useNewCashAddress) {
  network = network || networks.bitcoin
  useNewCashAddress = useNewCashAddress || false

  if ('cashAddrPrefix' in network && useNewCashAddress) {
    if (bscript.pubKeyHash.output.check(outputScript)) return toBase32(bscript.compile(outputScript).slice(3, 23), btemplates.types.P2PKH, network.cashAddrPrefix)
    if (bscript.scriptHash.output.check(outputScript)) return toBase32(bscript.compile(outputScript).slice(2, 22), btemplates.types.P2SH, network.cashAddrPrefix)
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
  try {
    if ('cashAddrPrefix' in network && useNewCashAddress) {
      decode = fromBase32(address)
      if (decode.prefix !== network.cashAddrPrefix) throw new Error(address + ' has an invalid prefix')
      if (decode.version === 'pubkeyhash') return bscript.pubKeyHash.output.encode(decode.hash)
      if (decode.version === 'scripthash') return bscript.scriptHash.output.encode(decode.hash)
    } else {
      decode = fromBase58Check(address)
      if (decode.version === network.pubKeyHash) return bscript.pubKeyHash.output.encode(decode.hash)
      if (decode.version === network.scriptHash) return bscript.scriptHash.output.encode(decode.hash)
    }
  } catch (e) {}

  if (!decode) {
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
  fromBase32: fromBase32,
  fromOutputScript: fromOutputScript,
  toBase58Check: toBase58Check,
  toBech32: toBech32,
  toBase32: toBase32,
  toOutputScript: toOutputScript
}
