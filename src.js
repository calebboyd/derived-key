"use strict";

exports.getYear = getYear;
exports.getIterationsFromYear = getIterationsFromYear;
exports.salt = salt;
exports.store = store;
exports.hash = hash;
exports.constantTimeCompare = constantTimeCompare;
exports.verify = verify;
var pbkdf2 = require("crypto").pbkdf2;
var randomBytes = require("crypto").randomBytes;


//hash formatting
var SEPARATOR = ".";
var ENCODING = "ascii";
var ITERATION_RADIX = 16;

//hash length
var KEY_LENGTH = 32;
var SALT_SIZE = 16;
var MAX_SAFE_INTEGER = 9007199254740991;

/**
 * Get the current year
 * @returns {number}
 */
function getYear() {
  return new Date().getFullYear();
}

/**
 * Get recommended iterations for pbkdf2 based on year
 * https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
 * @param year {number}
 * @returns {number}
 */
function getIterationsFromYear(year) {
  var iterations = Math.floor(Math.pow(2, (year - 2000) / 2) * 1000);
  if (iterations > MAX_SAFE_INTEGER) {
    iterations = MAX_SAFE_INTEGER;
  }
  return iterations;
}

/**
 * Return a random salt made of <size> bytes
 * @param size {number} Number of bytes the salt should be
 * @param cb {Function} (err,salt)
 */
function salt(size, cb) {
  randomBytes(Math.floor(size), function (err, rnd) {
    return cb(err || null, err ? void 0 : rnd);
  });
}

/**
 * Format the three pieces of information into a string for storage
 * @param iterations {number}
 * @param key {Buffer}
 * @param salt {Buffer}
 * @returns {string}
 */
function store(iterations, key, salt) {
  return iterations.toString(ITERATION_RADIX) + SEPARATOR + key.toString(ENCODING) + salt.toString(ENCODING);
}

/**
 * Create a hash from a secret
 * @param secret {string}
 * @param iterations {number}
 * @param cb {Function}
 */
function hash(secret, iterations, cb) {
  cb = cb || iterations;
  iterations = iterations === cb ? getIterationsFromYear(getYear()) : iterations;
  salt(SALT_SIZE, function (err, salt) {
    return err ? cb(err) : pbkdf2(secret, salt.toString(ENCODING), iterations, KEY_LENGTH, function (err, key) {
      return cb(err || null, err ? void 0 : store(iterations, key, salt));
    });
  });
}

/**
 * Compare two strings in constant time
 * //hapijs/cryptiles
 * @param a {string}
 * @param b {string}
 * @returns {boolean}
 */
function constantTimeCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }
  var mismatch = a.length === b.length ? 0 : 1;
  if (mismatch) {
    b = a;
  }

  for (var i = 0,
      il = a.length; i < il; ++i) {
    var ac = a.charCodeAt(i);
    var bc = b.charCodeAt(i);
    mismatch |= ac ^ bc;
  }
  return mismatch === 0;
}

/**
 * Verify a secret matches an existing hash
 * @param secret {string}
 * @param hash {string}
 * @param cb {Function}
 */
function verify(secret, hash, cb) {
  var _salt = hash.substring(hash.length - SALT_SIZE, hash.length);
  var iterations = parseInt(hash.split(SEPARATOR)[0], ITERATION_RADIX);
  pbkdf2(secret, _salt, iterations, KEY_LENGTH, function (err, key) {
    return cb(err || null, err ? void 0 : constantTimeCompare(hash, store(iterations, key, _salt)));
  });
}
