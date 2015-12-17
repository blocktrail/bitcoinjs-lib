/* global describe, it */

var assert = require('assert')
var bitcoin = require('../../')
var blockchain = require('./_blockchain')

describe('bitcoinjs-lib (advanced)', function () {
  it('can sign a Bitcoin message', function () {
    var key = bitcoin.ECKey.fromWIF('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss')
    var message = 'This is an example of a signed message.'

    var signature = bitcoin.Message.sign(key, message)
    assert.equal(signature.toString('base64'), 'G9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6ZTQZdSMCtkgoNmp17By9ItJr8o7ChX0XxY91nk=')
  })

  it('can verify a Bitcoin message', function () {
    var address = '1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN'
    var signature = 'HJLQlDWLyb1Ef8bQKEISzFbDAKctIlaqOpGbrk3YVtRsjmC61lpE5ErkPRUFtDKtx98vHFGUWlFhsh3DiW6N0rE'
    var message = 'This is an example of a signed message.'

    assert(bitcoin.Message.verify(address, signature, message))
  })

  it('can create an OP_RETURN transaction', function (done) {
    this.timeout(20000)

    var key = bitcoin.ECKey.fromWIF('L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy')
    var address = key.pub.getAddress(bitcoin.networks.testnet).toString()

    blockchain.t.faucet(address, 2e4, function (err, unspent) {
      if (err) return done(err)

      var tx = new bitcoin.TransactionBuilder()
      var data = new Buffer('bitcoinjs-lib')
      var dataScript = bitcoin.scripts.nullDataOutput(data)

      tx.addInput(unspent.txId, unspent.vout)
      tx.addOutput(dataScript, 1000)
      tx.sign(0, key)

      var txBuilt = tx.build()

      blockchain.t.transactions.propagate(txBuilt.toHex(), function (err) {
        if (err) return done(err)

        // check that the message was propagated
        blockchain.t.transactions.get(txBuilt.getId(), function (err, transaction) {
          if (err) return done(err)

          var actual = bitcoin.Transaction.fromHex(transaction.txHex)
          var dataScript2 = actual.outs[0].script
          var data2 = dataScript2.chunks[1]

          assert.deepEqual(dataScript, dataScript2)
          assert.deepEqual(data, data2)

          done()
        })
      })
    })
  })

  it('can create a transaction using OP_CHECKLOCKTIMEVERIFY', function (done) {
    this.timeout(30000)

    var network = bitcoin.networks.testnet
    var key = bitcoin.ECKey.makeRandom()
    var address = key.pub.getAddress(bitcoin.networks.testnet).toString()

    blockchain.t.faucet(address, 2e4, function (err, unspent) {
      if (err) return done(err)

      var tx = new bitcoin.TransactionBuilder(network)

      // now + 1 month
      var hodlDate = Math.floor((Date.now() + new Date(0).setMonth(1)) / 1000)
      var hodlLockTimeBuffer = new Buffer(4)
      hodlLockTimeBuffer.writeInt32LE(hodlDate | 0, 0)

      // {signature} {signature} or
      // OP_0 {signature} after 1 month
      var hodlScript = bitcoin.Script.fromChunks([
        bitcoin.opcodes.OP_IF,
        hodlLockTimeBuffer,
        bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY,
        bitcoin.opcodes.OP_DROP,
        bitcoin.opcodes.OP_ELSE,
        key.pub.toBuffer(),
        bitcoin.opcodes.OP_CHECKSIGVERIFY,
        bitcoin.opcodes.OP_ENDIF,
        key.pub.toBuffer(),
        bitcoin.opcodes.OP_CHECKSIG
      ])

      tx.addInput(unspent.txId, unspent.vout)
      tx.addOutput(hodlScript, 1000)
      tx.sign(0, key)

      var txBuilt = tx.build()

      blockchain.t.transactions.propagate(txBuilt.toHex(), function (err) {
        if (err) return done(err)

        // check that the message was propagated
        blockchain.t.transactions.get(txBuilt.getId(), function (err, transaction) {
          if (err) return done(err)

          var actual = bitcoin.Transaction.fromHex(transaction.txHex)
          var actualScript = actual.outs[0].script
          assert.deepEqual(actualScript, hodlScript)

          done()
        })
      })
    })
  })
})
