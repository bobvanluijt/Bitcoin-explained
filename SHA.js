/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/*  SHA simple, understanding SHA                                         (c) Bob van Luijt 2015  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

'use strict';

/**
 * SHA hash function reference implementation.
 *
 * @namespace
 */
var SHA = {};

/**
 * Generates an SHA hash
 * https://en.wikipedia.org/wiki/RSA_(cryptosystem)#A_working_example
 *
 * @returns {array} Result of sha generation
 */
SHA.generate = function(){
    /**
     * Calculate modular multiplicative inverse.
     * https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
     * Function based on PHP variant on http://rosettacode.org/wiki/Modular_inverse
     *
     * @param   {a} int
     * @param   {n} int
     * @returns {int} Result of modular multiplicative inverse.
     */
    function modular_multiplicative_inverse(a, n){
        if (n < 0){ n = -n; }
        if (a < 0){ a = n - (-a % n); }
    	var t  = 0;
        var nt = 1;
        var r  = n;
        var nr = a % n;
    	while (nr !== 0) {
    		var quot= (r/nr) | 0;
    		var tmp = nt;  nt = t - quot*nt;  t = tmp;
    		    tmp = nr;  nr = r - quot*nr;  r = tmp;
    	}
    	if (r > 1) { return -1; }
    	if (t < 0) { t += n; }
    	return t;
    }

    /**
     * Generates a random prime
     *
     * @param   {min} int, minimal value
     * @param   {max} int, maximal value
     * @returns {int} a random generated prime
     */
    function random_prime(min, max){
        var p = Math.floor(Math.random() * ((max - 1) - min + 1)) + min;
        if(bigInt(p).isPrime()===true){
            return p;
        } else {
            return random_prime(min, max);   
        } 
    }

    // generate values
    var p = random_prime(1, 255); // 8 bit
    var q = random_prime(1, 255); // 8 bit
    var n = p * q;
    var t = (p - 1) * (q - 1); // totient as φ(n) = (p − 1)(q − 1)
    var e = random_prime(1, t);
    var d = modular_multiplicative_inverse(e, t);
    return {
    	n: n, // public key (part I)
        e: e, // public key (part II)
        d: d  // private key
    };
};

/**
 * Encrypt
 * Uses BigInteger.js https://peterolson.github.com/BigInteger.js
 *
 * @param   {m} int, the 'message' to be encoded
 * @param   {n} int, n value returned from generate_sha() aka public key (part I)
 * @param   {e} int, e value returned from generate_sha() aka public key (part II)
 * @returns {int} encrypted hash
 */
SHA.encrypt = function(m, n, e){
	return bigInt(m).pow(e).mod(n);   
};

/**
 * Decrypt
 * Uses BigInteger.js https://peterolson.github.com/BigInteger.js
 *
 * @param   {mEnc} int, the 'message' to be decoded (encoded with SHA_encrypt())
 * @param   {d} int, d value returned from generate_sha() aka private key
 * @param   {n} int, n value returned from generate_sha() aka public key (part I)
 * @returns {int} decrypted hash
 */
SHA.decrypt = function(mEnc, d, n){
	return bigInt(mEnc).pow(d).mod(n);   
};
