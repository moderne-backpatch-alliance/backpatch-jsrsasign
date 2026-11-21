const assert = require('assert');
const rs = require('../lib/jsrsasign.js');

// RFC 9500 RSA1024 TEST PRIVATE KEY
let P5P = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCw0YNSqI9T1VFvRsIOejZ9feiKz1SgGfbe9Xq5tEzt2yJCsbyg
+xtcuCswNhdqY5A1ZN7G60HbL4/Hh/TlLhFJ4zNHVylz9mDDx3yp4IIcK2lb566d
fTD0B5EQ9Iqub4twLUdLKQCBfyhmJJvsEqKxm4J4QWgI+Brh/Pm3d4piPwIDAQAB
AoGASC6fj6TkLfMNdYHLQqG9kOlPfys4fstarpZD7X+fUBJ/H/7y5DzeZLGCYAIU
+QeAHWv6TfZIQjReW7Qy00RFJdgwFlTFRCsKXhG5x+IB+jL0Grr08KbgPPDgy4Jm
xirRHZVtU8lGbkiZX+omDIU28EHLNWL6rFEcTWao/tERspECQQDp2G5Nw0qYWn7H
Wm9Up1zkUTnkUkCzhqtxHbeRvNmHGKE7ryGMJEk2RmgHVstQpsvuFY4lIUSZEjAc
DUFJERhFAkEAwZH6O1ULORp8sHKDdidyleYcZU8L7y9Y3OXJYqELfddfBgFUZeVQ
duRmJj7ryu0g0uurOTE+i8VnMg/ostxiswJBAOc64Dd8uLJWKa6uug+XPr91oi0n
OFtM+xHrNK2jc+WmcSg3UJDnAI3uqMc5B+pERLq0Dc6hStehqHjUko3RnZECQEGZ
eRYWciE+Cre5dzfZkomeXE0xBrhecV0bOq6EKWLSVE+yr6mAl05ThRK9DCfPSOpy
F6rgN3QiyCA9J/1FluUCQQC5nX+PTU1FXx+6Ri2ZCi6EjEKMHr7gHcABhMinZYOt
N59pra9UdVQw9jxCU9G7eMyb0jJkNACAuEwakX3gi27b
-----END RSA PRIVATE KEY-----`;

let prvobj = rs.KEYUTIL.getKey(P5P);
let pubobj = rs.KEYUTIL.getKey({n: prvobj.n.toString(16), e: prvobj.e.toString(16)});
let CY = rs.KJUR.crypto.Cipher;

describe("CVE-2024-21484 RSA encryption removed", function() {
    it('RSAKey has no encrypt, encryptOAEP, decrypt or decryptOAEP', function() {
	assert.equal(typeof rs.RSAKey.prototype.encrypt, "undefined");
	assert.equal(typeof rs.RSAKey.prototype.encryptOAEP, "undefined");
	assert.equal(typeof rs.RSAKey.prototype.decrypt, "undefined");
	assert.equal(typeof rs.RSAKey.prototype.decryptOAEP, "undefined");
	assert.equal(typeof prvobj.decrypt, "undefined");
	assert.equal(typeof prvobj.decryptOAEP, "undefined");
    });
    it('Cipher.encrypt rejects an RSA public key', function() {
	assert.throws(function() { CY.encrypt("aaa", pubobj); });
	assert.throws(function() { CY.encrypt("aaa", pubobj, "RSAOAEP"); });
    });
    it('Cipher.decrypt rejects an RSA private key', function() {
	let c = "00".repeat(128);
	assert.throws(function() { CY.decrypt(c, prvobj); });
	assert.throws(function() { CY.decrypt(c, prvobj, "RSAOAEP"); });
    });
    it('Cipher is not exported from the npm entry point', function() {
	assert.equal(rs.Cipher, undefined);
    });
});
