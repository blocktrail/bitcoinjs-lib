/* global describe, it */

var assert = require('assert')
var types = require('../src/types')
var typeforce = require('typeforce')

describe('types', function () {
  describe('BigInt/ECPoint', function () {
    it('return true for duck types', function () {
      assert(types.BigInt(new function BigInteger () {}))
      assert(types.ECPoint(new function Point () {}))
    })

    it('return false for bad types', function () {
      assert(!types.BigInt(new function NotABigInteger () {}))
      assert(!types.ECPoint(new function NotAPoint () {}))
    })
  })

  describe('Buffer Hash160/Hash256', function () {
    var buffer20byte = new Buffer((new Array(20 + 1)).join('00'), 'hex')
    var buffer32byte = new Buffer((new Array(32 + 1)).join('00'), 'hex')

    it('return true for correct size', function () {
      assert(types.Hash160bit(buffer20byte))
      assert(types.Hash256bit(buffer32byte))
    })

    it('return false for incorrect size', function () {
      assert(!types.Hash160bit(buffer32byte), "32 byte buffer != Hash160")
      assert(!types.Hash256bit(buffer20byte), "20 byte buffer != Hash256")
    })

    it('return true for oneOf', function () {
      assert(typeforce(types.oneOf(types.Hash256bit, types.Hash160bit), buffer32byte), "Hash256 first")
      assert(typeforce(types.oneOf(types.Hash160bit, types.Hash256bit), buffer32byte), "Hash160 first")
    })
  })
})
