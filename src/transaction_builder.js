var baddress = require('./address')
var bcrypto = require('./crypto')
var bscript = require('./script')
var bufferEquals = require('buffer-equals')
var networks = require('./networks')
var ops = require('./opcodes')
var typeforce = require('typeforce')
var types = require('./types')

var ECPair = require('./ecpair')
var ECSignature = require('./ecsignature')
var Transaction = require('./transaction')

// re-orders signatures to match pubKeys, fills undefined otherwise
function fixMSSignatures (transaction, vin, pubKeys, signatures, prevOutScript, hashType, skipPubKey) {
  // maintain a local copy of unmatched signatures
  var unmatched = signatures.slice()
  var cache = {}

  return pubKeys.map(function (pubKey) {
    // skip optionally provided pubKey
    if (skipPubKey && bufferEquals(skipPubKey, pubKey)) return undefined

    var matched
    var keyPair2 = ECPair.fromPublicKeyBuffer(pubKey)

    // check for a matching signature
    unmatched.some(function (signature, i) {
      // skip if undefined || OP_0
      if (!signature) return false

      var signatureHash = cache[hashType] = cache[hashType] || transaction.hashForSignature(vin, prevOutScript, hashType)
      if (!keyPair2.verify(signatureHash, signature)) return false

      // remove matched signature from unmatched
      unmatched[i] = undefined
      matched = signature

      return true
    })

    return matched || undefined
  })
}

function extractInput (transaction, txIn, vin) {
  var redeemScript
  var scriptSig = txIn.script
  var scriptSigChunks = bscript.decompile(scriptSig)

  var prevOutScript
  var prevOutType = bscript.classifyInput(scriptSig, true)
  var scriptType

  if (scriptSig.length === 0 && txIn.witness && txIn.witness.length === 2) {
    prevOutType = 'segwitpubkeyhash'
  }

  // console.log('extractInput.scriptSigChunks', scriptSigChunks)

  // Re-classify if segwitpubkeyhash as scriptHash
  // @TODO: this needs rework, probably need to start passing witness to classifyInput and work from there ...
  if (scriptSigChunks.length === 1 && txIn.witness && txIn.witness.length === 2) {
    prevOutType = 'scripthash'
    scriptType = 'segwitpubkeyhash'

    redeemScript = scriptSigChunks[0]
    prevOutScript = bscript.scriptHashOutput(bcrypto.hash160(redeemScript))

  // Re-classify if scriptHash
  } else if (prevOutType === 'scripthash') {
    redeemScript = scriptSigChunks.slice(-1)[0]
    // console.log('extractInput.redeemScript', redeemScript)

    prevOutScript = bscript.scriptHashOutput(bcrypto.hash160(redeemScript))

    scriptSig = bscript.compile(scriptSigChunks.slice(0, -1))

    scriptSigChunks = scriptSigChunks.slice(0, -1)

    scriptType = bscript.classifyInput(scriptSig, true)
  } else {
    scriptType = prevOutType
  }

  // console.log('extractInput.prevOutType', prevOutType)
  // console.log('extractInput.scriptType', scriptType)

  // pre-empt redeemScript decompilation
  var redeemScriptChunks
  if (redeemScript) {
    redeemScriptChunks = bscript.decompile(redeemScript)
  }

  // Extract hashType, pubKeys and signatures
  var hashType, parsed, pubKeys, signatures

  switch (scriptType) {
    case 'pubkeyhash':
      parsed = ECSignature.parseScriptSignature(scriptSigChunks[0])
      hashType = parsed.hashType
      pubKeys = scriptSigChunks.slice(1)
      signatures = [parsed.signature]
      prevOutScript = bscript.pubKeyHashOutput(bcrypto.hash160(pubKeys[0]))

      break

    case 'pubkey':
      parsed = ECSignature.parseScriptSignature(scriptSigChunks[0])
      hashType = parsed.hashType
      signatures = [parsed.signature]

      if (redeemScript) {
        pubKeys = redeemScriptChunks.slice(0, 1)
      }

      break

    case 'multisig':
      signatures = scriptSigChunks.slice(1).map(function (chunk) {
        if (chunk === ops.OP_0) return undefined

        var parsed = ECSignature.parseScriptSignature(chunk)
        hashType = parsed.hashType

        return parsed.signature
      })

      if (redeemScript) {
        pubKeys = redeemScriptChunks.slice(1, -2)

        if (pubKeys.length !== signatures.length) {
          signatures = fixMSSignatures(transaction, vin, pubKeys, signatures, redeemScript, hashType, redeemScript)
        }
      }

      break

    case 'segwitpubkeyhash':
      parsed = ECSignature.parseScriptSignature(txIn.witness[0])
      hashType = parsed.hashType
      pubKeys = [txIn.witness[1]]
      signatures = [parsed.signature]
      prevOutScript = bscript.segWitPubKeyHashOutput(bcrypto.hash160(pubKeys[0]))

      break
  }

  return {
    hashType: hashType,
    prevOutScript: prevOutScript,
    prevOutType: prevOutType,
    pubKeys: pubKeys,
    redeemScript: redeemScript,
    scriptType: scriptType,
    signatures: signatures,
    witness: txIn.witness || []
  }
}

function TransactionBuilder (network) {
  this.prevTxMap = {}
  this.prevOutScripts = {}
  this.prevOutTypes = {}
  this.network = network || networks.bitcoin

  this.inputs = []
  this.tx = new Transaction()
}

TransactionBuilder.prototype.setLockTime = function (locktime) {
  typeforce(types.UInt32, locktime)

  // if any signatures exist, throw
  if (this.inputs.some(function (input) {
    if (!input.signatures) return false

    return input.signatures.some(function (s) { return s })
  })) {
    throw new Error('No, this would invalidate signatures')
  }

  this.tx.locktime = locktime
}

TransactionBuilder.fromTransaction = function (transaction, network) {
  var txb = new TransactionBuilder(network)

  // Copy other transaction fields
  txb.tx.version = transaction.version
  txb.tx.locktime = transaction.locktime

  // Extract/add inputs
  transaction.ins.forEach(function (txIn) {
    txb.addInput(txIn.hash, txIn.index, txIn.sequence)
  })

  // Extract/add outputs
  transaction.outs.forEach(function (txOut) {
    txb.addOutput(txOut.script, txOut.value)
  })

  // Extract/add signatures
  txb.inputs = transaction.ins.map(function (txIn, vin) {
    // TODO: verify whether extractInput is sane with coinbase scripts
    if (Transaction.isCoinbaseHash(txIn.hash)) {
      throw new Error('coinbase inputs not supported')
    }

    // Ignore empty scripts
    // if (txIn.script.length === 0) return {}

    return extractInput(transaction, txIn, vin)
  })

  return txb
}

TransactionBuilder.prototype.addInput = function (txHash, vout, sequence, prevOutScript) {
  // is it a hex string?
  if (typeof txHash === 'string') {
    // transaction hashs's are displayed in reverse order, un-reverse it
    txHash = [].reverse.call(new Buffer(txHash, 'hex'))

  // is it a Transaction object?
  } else if (txHash instanceof Transaction) {
    prevOutScript = txHash.outs[vout].script
    txHash = txHash.getHash()
  }

  var input = {}
  if (prevOutScript) {
    var prevOutScriptChunks = bscript.decompile(prevOutScript)
    var prevOutType = bscript.classifyOutput(prevOutScriptChunks)

    // if we can, extract pubKey information
    switch (prevOutType) {
      case 'multisig':
        input.pubKeys = prevOutScriptChunks.slice(1, -2)
        input.signatures = input.pubKeys.map(function () { return undefined })

        break

      case 'pubkey':
        input.pubKeys = prevOutScriptChunks.slice(0, 1)
        input.signatures = [undefined]

        break
    }

    if (prevOutType !== 'scripthash' && prevOutType !== 'segwitscripthash') {
      input.scriptType = prevOutType
    }

    input.prevOutScript = prevOutScript
    input.prevOutType = prevOutType
  }

  // if signatures exist, adding inputs is only acceptable if SIGHASH_ANYONECANPAY is used
  // throw if any signatures *didn't* use SIGHASH_ANYONECANPAY
  if (!this.inputs.every(function (otherInput) {
    // no signature
    if (otherInput.hashType === undefined) return true

    return otherInput.hashType & Transaction.SIGHASH_ANYONECANPAY
  })) {
    throw new Error('No, this would invalidate signatures')
  }

  var prevOut = txHash.toString('hex') + ':' + vout
  if (this.prevTxMap[prevOut]) throw new Error('Transaction is already an input')

  var vin = this.tx.addInput(txHash, vout, sequence)
  this.inputs[vin] = input
  this.prevTxMap[prevOut] = vin

  return vin
}

TransactionBuilder.prototype.addOutput = function (scriptPubKey, value) {
  var nOutputs = this.tx.outs.length

  // if signatures exist, adding outputs is only acceptable if SIGHASH_NONE or SIGHASH_SINGLE is used
  // throws if any signatures didn't use SIGHASH_NONE|SIGHASH_SINGLE
  if (!this.inputs.every(function (input, index) {
    // no signature
    if (input.hashType === undefined) return true

    var hashTypeMod = input.hashType & 0x1f
    if (hashTypeMod === Transaction.SIGHASH_NONE) return true
    if (hashTypeMod === Transaction.SIGHASH_SINGLE) {
      // account for SIGHASH_SINGLE signing of a non-existing output, aka the "SIGHASH_SINGLE" bug
      return index < nOutputs
    }

    return false
  })) {
    throw new Error('No, this would invalidate signatures')
  }

  // Attempt to get a script if it's a base58 address string
  if (typeof scriptPubKey === 'string') {
    scriptPubKey = baddress.toOutputScript(scriptPubKey, this.network)
  }

  return this.tx.addOutput(scriptPubKey, value)
}

TransactionBuilder.prototype.build = function () {
  return this.__build(false)
}
TransactionBuilder.prototype.buildIncomplete = function () {
  return this.__build(true)
}

var canBuildTypes = {
  'multisig': true,
  'pubkey': true,
  'pubkeyhash': true,
  'segwitpubkeyhash': true
}

TransactionBuilder.prototype.__build = function (allowIncomplete) {
  if (!allowIncomplete) {
    if (!this.tx.ins.length) throw new Error('Transaction has no inputs')
    if (!this.tx.outs.length) throw new Error('Transaction has no outputs')
  }

  var tx = this.tx.clone()

  // Create script signatures from inputs
  this.inputs.forEach(function (input, index) {
    // console.log('build', index, input)

    var scriptType = input.scriptType
    var scriptSig
    var witness
    var pkhSignature

    if (!allowIncomplete) {
      if (!scriptType) throw new Error('Transaction is not complete')
      if (!canBuildTypes[scriptType]) throw new Error(scriptType + ' not supported')

      // XXX: only relevant to types that need signatures
      if (!input.signatures) throw new Error('Transaction is missing signatures')
    }

    if (input.signatures) {
      switch (scriptType) {
        case 'pubkeyhash':
          pkhSignature = input.signatures[0].toScriptSignature(input.hashType)
          scriptSig = bscript.pubKeyHashInput(pkhSignature, input.pubKeys[0])
          break

        case 'multisig':
          var msSignatures = input.signatures.map(function (signature) {
            return signature && signature.toScriptSignature(input.hashType)
          })

          // fill in blanks with OP_0
          if (allowIncomplete) {
            for (var i = 0; i < msSignatures.length; ++i) {
              msSignatures[i] = msSignatures[i] || ops.OP_0
            }

          // remove blank signatures
          } else {
            msSignatures = msSignatures.filter(function (x) { return x })
          }

          var redeemScript = allowIncomplete ? undefined : input.redeemScript
          scriptSig = bscript.multisigInput(msSignatures, redeemScript)

          console.log('input.segWitScript', input.segWitScript)

          if (input.witness) {
            var scriptSigChunks = bscript.decompile(scriptSig)
            witness = input.witness
            witness[1] = scriptSigChunks[1]
            scriptSig = bscript.compile([input.segWitScript])
          }
          break

        case 'pubkey':
          var pkSignature = input.signatures[0].toScriptSignature(input.hashType)
          scriptSig = bscript.pubKeyInput(pkSignature)
          break

        case 'segwitpubkeyhash':
          pkhSignature = input.signatures[0].toScriptSignature(input.hashType)
          witness = input.witness
          witness[0] = pkhSignature
          scriptSig = new Buffer('')
          break
      }
    }

    // did we build a scriptSig?
    if (scriptSig) {
      // wrap as scriptHash if necessary
      if (input.prevOutType === 'scripthash' && !input.witness) {
        scriptSig = bscript.scriptHashInput(scriptSig, input.redeemScript)
      }

      tx.setInputScript(index, scriptSig, witness)
    }
  })

  return tx
}

TransactionBuilder.prototype.sign = function (index, keyPair, redeemScript, hashType, segWit, amount, segWitScript) {
  if (keyPair.network !== this.network) throw new Error('Inconsistent network')
  if (!this.inputs[index]) throw new Error('No input at index: ' + index)
  hashType = hashType || Transaction.SIGHASH_ALL

  var input = this.inputs[index]
  var canSign = input.hashType &&
    input.prevOutScript &&
    input.prevOutType &&
    input.pubKeys &&
    input.scriptType &&
    input.signatures &&
    input.signatures.length === input.pubKeys.length

  var kpPubKey = keyPair.getPublicKeyBuffer()

  // are we ready to sign?
  if (canSign) {
    // if redeemScript was provided, enforce consistency
    if (redeemScript && input.redeemScript) {
      if (!bufferEquals(input.redeemScript, redeemScript)) throw new Error('Inconsistent redeemScript')
    }

    if (input.hashType !== hashType) throw new Error('Inconsistent hashType')

  // no? prepare
  } else {
    // must be pay-to-scriptHash?

    // console.log('redeemScript', redeemScript)

    if (redeemScript) {
      // if we have a prevOutScript, enforce scriptHash equality to the redeemScript
      if (input.prevOutScript) {
        if (input.prevOutType !== 'scripthash') throw new Error('PrevOutScript must be P2SH')

        var scriptHash = bscript.decompile(input.prevOutScript)[1]
        if (!bufferEquals(scriptHash, bcrypto.hash160(redeemScript))) throw new Error('RedeemScript does not match ' + scriptHash.toString('hex'))
      }

      var scriptType = bscript.classifyOutput(redeemScript)
      var redeemScriptChunks = bscript.decompile(redeemScript)
      var pubKeys, pkh1, pkh2

      switch (scriptType) {
        case 'multisig':
          pubKeys = redeemScriptChunks.slice(1, -2)

          if (segWit) {
            input.witness = [new Buffer(''), undefined, redeemScript]
          }

          break

        case 'pubkeyhash':
          pkh1 = redeemScriptChunks[2]
          pkh2 = bcrypto.hash160(keyPair.getPublicKeyBuffer())

          if (!bufferEquals(pkh1, pkh2)) throw new Error('privateKey cannot sign for this input')
          pubKeys = [kpPubKey]

          break

        case 'pubkey':
          pubKeys = redeemScriptChunks.slice(0, 1)

          break

        case 'segwitpubkeyhash':
          pkh1 = redeemScriptChunks.slice(1)[0]
          pkh2 = bcrypto.hash160(keyPair.getPublicKeyBuffer())

          if (!bufferEquals(pkh1, pkh2)) throw new Error('privateKey cannot sign for this input')
          pubKeys = [kpPubKey]

          input.witness = [undefined, kpPubKey]
          input.signatureScript = bscript.pubKeyHashOutput(bcrypto.hash160(keyPair.getPublicKeyBuffer()))

          break

        default:
          throw new Error('RedeemScript not supported (' + scriptType + ')')
      }

      // if we don't have a prevOutScript, generate a P2SH script
      if (!input.prevOutScript) {
        input.prevOutScript = bscript.scriptHashOutput(bcrypto.hash160(redeemScript))
        input.prevOutType = 'scripthash'
      }

      input.pubKeys = pubKeys
      input.redeemScript = redeemScript
      input.segWitScript = segWitScript
      input.scriptType = scriptType
      input.signatures = pubKeys.map(function () { return undefined })
    } else {
      // pay-to-scriptHash is not possible without a redeemScript
      if (input.prevOutType === 'scripthash') throw new Error('PrevOutScript is P2SH, missing redeemScript')

      // console.log('input.pubKeys', input.pubKeys)
      // console.log('input.scriptType', input.scriptType)
      // console.log('segWit', segWit)

      // if we don't have a scriptType, assume pubKeyHash otherwise
      if (!input.scriptType) {
        if (segWit) {
          input.prevOutScript = bscript.segWitPubKeyHashOutput(bcrypto.hash160(keyPair.getPublicKeyBuffer()))
          input.prevOutType = 'segwitpubkeyhash'
          input.witness = [undefined, kpPubKey]
          input.signatureScript = bscript.pubKeyHashOutput(bcrypto.hash160(keyPair.getPublicKeyBuffer()))
        } else {
          input.prevOutScript = bscript.pubKeyHashOutput(bcrypto.hash160(keyPair.getPublicKeyBuffer()))
          input.prevOutType = 'pubkeyhash'
        }

        input.pubKeys = [kpPubKey]
        input.scriptType = input.prevOutType
        input.signatures = [undefined]
      } else {
        // throw if we can't sign with it
        if (!input.pubKeys || !input.signatures) throw new Error(input.scriptType + ' not supported')
      }
    }

    input.hashType = hashType
  }

  // ready to sign?
  var signatureScript = input.redeemScript || input.prevOutScript
  var signatureHash = this.tx.hashForSignature(index, signatureScript, hashType, segWit, amount)

  // enforce in order signing of public keys
  var valid = input.pubKeys.some(function (pubKey, i) {
    if (false) {
      console.log(index, i)
      console.log(!!input.signatures[0], !!input.signatures[1])
      if (index === 0) {
        if (i === 0 && !input.signatures[0]) {
          input.signatures[0] = ECSignature.fromDER(new Buffer('30440220121a629bb5fee3ecaf3e7a0b111101c51de816f427eaedd992b57f49b69b228e0220402ecd144a7321b4bad6ba3bfa5876b755b9c52a8c8ab17a33830d5929a76cbe', 'hex'))
          return true
        } else if (i === 1 && !input.signatures[1]) {
          input.signatures[1] = ECSignature.fromDER(new Buffer('3045022100f4770442f8509c8065638482fb1eca0ccaed18d740551cb53abe09a6675d94c5022068f6a904e6bf4a639bbb0aaa1870c137a64717a1d53b47b14e584cf0e05cf750', 'hex'))
          return true
        }
      } else if (index === 1) {
        if (i === 0 && !input.signatures[0]) {
          input.signatures[0] = ECSignature.fromDER(new Buffer('304402207a58fb0fa45e59352e018e1d48b4905657504418d75a11ba34685b585da65de5022040f27e9790ec1719fe63fb5bd01e1f73be43ff2a165d08a4ba225ef60892d545', 'hex'))
          return true
        } else if (i === 1 && !input.signatures[1]) {
          input.signatures[1] = ECSignature.fromDER(new Buffer('3045022100ba06ddc5cacaac6e43c0d813d53eec8705124505f24064bee361d41dd54fd84702207d9f382f7fc6db8efcab713ee09e28493c4081a2194f003e00981c389e26fa00', 'hex'))
          return true
        }
      }
    }

    if (!bufferEquals(kpPubKey, pubKey)) return false
    if (input.signatures[i]) throw new Error('Signature already exists')

    var signature = keyPair.sign(signatureHash)

    // console.log('sign', keyPair.toWIF(), signatureHash, signature.toDER())
    input.signatures[i] = signature

    return true
  })

  if (!valid) throw new Error('Key pair cannot sign for this input')
}

module.exports = TransactionBuilder
