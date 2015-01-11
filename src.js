exports.getYear = getYear;
exports.getIterationsFromYear = getIterationsFromYear;
exports.salt = salt;
exports.store = store;
exports.hash = hash;
exports.constantTimeCompare = constantTimeCompare;
exports.verify = verify;
var pbkdf2 = require('crypto').pbkdf2;
var randomBytes = require('crypto').randomBytes;


// Iterations(HEX)|Key+Salt(ENCODING)
var SEPARATOR = "|";
var ENCODING = "ascii";
var ENCODING_BYTE_LENGTH = 1;
var KEY_LENGTH = 32 * ENCODING_BYTE_LENGTH;
var SALT_SIZE = 16 * ENCODING_BYTE_LENGTH;
var MAX_KEY_CHARS = 1024;
var ITERATION_RADIX = 16;
var MAX_SAFE_INTEGER = 9007199254740991;

function getYear() {
  return (new Date()).getFullYear();
}

function getIterationsFromYear(year) {
  var iterations = Math.floor(Math.pow(2, (year - 2000) / 2) * 1000);
  if (iterations > MAX_SAFE_INTEGER) {
    iterations = MAX_SAFE_INTEGER;
  }
  return iterations;
}

function salt(size, cb) {
  randomBytes(Math.floor(size), function (err, rnd) {
    return cb(err || null, err ? void 0 : rnd);
  });
}

function store(iterations, key, salt) {
  return (iterations.toString(ITERATION_RADIX) + SEPARATOR + key.toString(ENCODING) + salt.toString(ENCODING));
}

function hash(secret, iterations, cb) {
  cb = cb || iterations;
  iterations = iterations === cb ? getIterationsFromYear(getYear()) : iterations;
  salt(SALT_SIZE, function (err, salt) {
    return err && cb(err) || pbkdf2(secret, salt, iterations, KEY_LENGTH, function (err, key) {
      return cb(err || null, err ? void 0 : store(iterations, key, salt));
    });
  });
}

function constantTimeCompare(a, b) {
  //Run Un-optimized in most runtimes
  with ({}) {
    // Add at least one character so that there's at least one thing to modulo over.
    a += " ";
    b += " ";
    var aLen = a.length, bLen = b.length, match = aLen === bLen ? 1 : 0, i = Math.max(aLen, bLen, MAX_KEY_CHARS);
    while (i--) {
      // We repeat the comparison over the strings with % so that we do not compare
      // a number to NaN, since that has different timing that comparing two numbers.
      match &= a.charCodeAt(i % aLen) === b.charCodeAt(i % bLen) ? 1 : 0;
    }
    return match === 1;
  }
}

function verify(secret, hash, cb) {
  var salt = hash.substring(hash.length - SALT_SIZE, hash.length);
  var iterations = parseInt(hash.split(SEPARATOR)[0], ITERATION_RADIX);
  pbkdf2(secret, salt, iterations, KEY_LENGTH, function (err, key) {
    return cb(err || null, err ? void 0 : constantTimeCompare(hash, store(iterations, key, salt)));
  });
}
