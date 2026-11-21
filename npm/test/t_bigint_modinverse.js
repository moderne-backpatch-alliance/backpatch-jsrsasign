var assert = require('assert');
var rs = require('../lib/jsrsasign.js');
var BigInteger = rs.BigInteger;

// ported from test/qunit-do-crypto.html (upstream ca5b027)
describe("BigInteger.modInverse", function() {
  it("returns quickly for zero input", function() {
    var biM = new BigInteger("97", 10);
    var biR = new BigInteger("0", 10).modInverse(biM);
    assert.equal(biR.compareTo(BigInteger.ZERO), 0, "0 has no inverse");
  });

  it("normalizes negative input", function() {
    var biM1 = new BigInteger("7", 10);
    var biM2 = new BigInteger("97", 10);
    assert.equal(new BigInteger("-1", 10).modInverse(biM1).toString(10), "6", "-1 mod 7");
    assert.equal(new BigInteger("-13", 10).modInverse(biM2).toString(10), "82", "-13 mod 97");
  });
});
