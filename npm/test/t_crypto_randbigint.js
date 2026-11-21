var assert = require('assert');
var rs = require('../lib/jsrsasign.js');
var BigInteger = rs.BigInteger;
var Util = rs.KJUR.crypto.Util;

describe("KJUR.crypto.Util random BigInteger range", function() {
    it('getRandomBigIntegerZeroToMax rejects out-of-range candidate', function() {
	var fOrig = Util.getRandomBigIntegerOfNbits;
	var aBiRand = [new BigInteger("200", 10), new BigInteger("42", 10)];
	var idx = 0;
	Util.getRandomBigIntegerOfNbits = function(n) {
	    return aBiRand[idx++];
	};
	try {
	    var bi = Util.getRandomBigIntegerZeroToMax(new BigInteger("100", 10));
	    assert.equal(bi.toString(10), "42", "returns in-range value");
	    assert.equal(idx >= 2, true, "retries when out-of-range candidate appears");
	} finally {
	    Util.getRandomBigIntegerOfNbits = fOrig;
	}
    });
    it('getRandomBigIntegerMinToMax throws for any positive compareTo', function() {
	var biMin = {
	    compareTo: function(a) { return 2; }
	};
	var biMax = {
	    subtract: function(a) { throw "subtract must not be called"; }
	};
	var ex = null;
	try {
	    Util.getRandomBigIntegerMinToMax(biMin, biMax);
	} catch (err) {
	    ex = err;
	}
	assert.equal(ex, "biMin is greater than biMax", "throws before subtraction");
    });
});
