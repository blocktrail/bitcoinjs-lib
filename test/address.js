/* global describe, it */

var assert = require('assert')
var baddress = require('../src/address')
var networks = require('../src/networks')
var bscript = require('../src/script')
var fixtures = require('./fixtures/address.json')

describe('address', function () {
  describe('fromBase58Check', function () {
    fixtures.standard.forEach(function (f) {
      if (!f.base58check) return

      it('decodes ' + f.base58check, function () {
        var decode = baddress.fromBase58Check(f.base58check)

        assert.strictEqual(decode.version, f.version)
        assert.strictEqual(decode.hash.toString('hex'), f.hash)
      })
    })

    fixtures.invalid.fromBase58Check.forEach(function (f) {
      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          baddress.fromBase58Check(f.address)
        }, new RegExp(f.address + ' ' + f.exception))
      })
    })
  })

  describe('fromCashAddress', function () {
    fixtures.standard.forEach(function (f) {
      if (!f.cashaddr) return

      it('decodes ' + f.cashaddr, function () {
        var decode = baddress.fromCashAddress(f.cashaddr)

        assert.strictEqual(decode.version, f.version)
        assert.strictEqual(decode.hash.toString('hex'), f.hash)
      })
    })

    fixtures.invalid.fromCashAddress.forEach(function (f) {
      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          baddress.fromCashAddress(f.address)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('fromBech32', function () {
    fixtures.standard.forEach((f) => {
      if (!f.bech32) return

      it('decodes ' + f.bech32, function () {
        var actual = baddress.fromBech32(f.bech32)

        assert.strictEqual(actual.version, f.version)
        assert.strictEqual(actual.prefix, networks[f.network].bech32)
        assert.strictEqual(actual.data.toString('hex'), f.data)
      })
    })

    fixtures.invalid.bech32.forEach((f, i) => {
      it('decode fails for ' + f.bech32 + '(' + f.exception + ')', function () {
        assert.throws(function () {
          baddress.fromBech32(f.address)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('fromOutputScript', function () {
    fixtures.standard.forEach(function (f) {
      it('encodes ' + f.script.slice(0, 30) + '... (' + f.network + ')', function () {
        var script = bscript.fromASM(f.script)
        var allowCash = 'cashaddr' in f
        var address = baddress.fromOutputScript(script, networks[f.network], allowCash)

        if (f.base58check) {
          assert.strictEqual(address, f.base58check)
        } else if (f.bech32) {
          assert.strictEqual(address, f.bech32.toLowerCase())
        } else if (f.base32) {
          assert.strictEqual(address, f.base32.toLowerCase())
        }
      })
    })

    fixtures.invalid.fromOutputScript.forEach(function (f) {
      it('throws when ' + f.script.slice(0, 30) + '... ' + f.exception, function () {
        var script = bscript.fromASM(f.script)

        assert.throws(function () {
          baddress.fromOutputScript(script)
        }, new RegExp(f.script + ' ' + f.exception))
      })
    })
  })

  describe('toBase58Check', function () {
    fixtures.standard.forEach(function (f) {
      if (!f.base58check) return

      it('encodes ' + f.hash + ' (' + f.network + ')', function () {
        var address = baddress.toBase58Check(Buffer.from(f.hash, 'hex'), f.version)

        assert.strictEqual(address, f.base58check)
      })
    })
  })

  describe('toBech32', function () {
    fixtures.bech32.forEach((f, i) => {
      if (!f.bech32) return
      var data = Buffer.from(f.data, 'hex')

      it('encode ' + f.address, function () {
        assert.deepEqual(baddress.toBech32(data, f.version, f.prefix), f.address)
      })
    })

    fixtures.invalid.bech32.forEach((f, i) => {
      if (!f.prefix || f.version === undefined || f.data === undefined) return

      it('encode fails (' + f.exception, function () {
        assert.throws(function () {
          baddress.toBech32(Buffer.from(f.data, 'hex'), f.version, f.prefix)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('toOutputScript', function () {
    it('fails when short cashaddr is used on wrong network', function () {
      var bch = networks.bitcoincash
      var tbch = networks.bitcoincashtestnet
      var fullAddress = 'bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a'
      var shortAddress = 'qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a'

      var script1 = baddress.toOutputScript(fullAddress, bch, true)
      var script2 = baddress.toOutputScript(shortAddress, bch, true)
      assert.strictEqual(script1.toString('hex'), script2.toString('hex'))

      var e
      try {
        baddress.toOutputScript(shortAddress, tbch, true)
      } catch (_e) {
        e = _e
        assert.ok("qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a has no matching Script" == _e.message)
      }
      assert.ok(e)
    })

    fixtures.standard.forEach(function (f) {
      it('decodes ' + f.script.slice(0, 30) + '... (' + f.network + ')', function () {
        var script;
        if (f.base58check) {
          script = baddress.toOutputScript(f.base58check || f.bech32, networks[f.network])
        } else if (f.bech32) {
          script = baddress.toOutputScript(f.bech32, networks[f.network])
        } else if (f.cashaddr) {
          var prefixLen = networks[f.network].cashAddrPrefix.length
          if (f.cashaddr.slice(prefixLen) === networks[f.network].cashAddrPrefix) {
            // do one with sliced off prefix fixture
            script = baddress.toOutputScript(f.cashaddr.slice(prefixLen + 1), networks[f.network], true)
            assert.strictEqual(bscript.toASM(script), f.script)
          }
          // do one with default test fixture
          script = baddress.toOutputScript(f.cashaddr, networks[f.network], true)
        }
        assert.strictEqual(bscript.toASM(script), f.script)
      })
    })

    fixtures.invalid.toOutputScript.forEach(function (f) {
      it('throws when ' + f.exception, function () {
        assert.throws(function () {
          baddress.toOutputScript(f.address, f.network)
        }, new RegExp(f.address + ' ' + f.exception))
      })
    })
  })
})
