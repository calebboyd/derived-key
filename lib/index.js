'use strict';

Object.defineProperty(exports, '__esModule', {
  value: true
});

var _slicedToArray = (function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i['return']) _i['return'](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError('Invalid attempt to destructure non-iterable instance'); } }; })();

exports.getYear = getYear;
exports.getIterationsFromYear = getIterationsFromYear;
exports.salt = salt;
exports.store = store;
exports.hash = hash;
exports.verify = verify;

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }

var _crypto = require('crypto');

var _urlsafeBase64 = require('urlsafe-base64');

var _bufferEqualConstantTime = require('buffer-equal-constant-time');

var _bufferEqualConstantTime2 = _interopRequireDefault(_bufferEqualConstantTime);

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
 * Start with 1000 iterations in y2k double every 2 years thereafter
 * https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
 * @param year {number}
 * @returns {number}
 */

function getIterationsFromYear(year) {
  var iterations = Math.floor(Math.pow(2, (year - 2000) / 2) * 1000);
  if (iterations > MAX_SAFE_INTEGER) {
    return MAX_SAFE_INTEGER;
  }
  return iterations;
}

/**
 * Return a random salt made of <size> bytes
 * @param size {number} Number of bytes the salt should be
 * @param cb {Function} (err,salt)
 */

function salt(size, cb) {
  if (size === undefined) size = SALT_SIZE;

  (0, _crypto.randomBytes)(Math.floor(size), cb);
}

/**
 * Format the three pieces of information into a string for storage
 * @param iterations {number}
 * @param key {Buffer|string}
 * @param salt {Buffer|string}
 * @returns {string}
 */

function store(iterations, key, salt) {
  return iterations.toString(16) + '.' + (0, _urlsafeBase64.encode)(key) + '.' + (0, _urlsafeBase64.encode)(salt);
}

/**
 * Create a hash from a secret
 * @param secret {string}
 * @param iterations {number}
 * @param cb {Function}
 */

function hash(secret) {
  var _ref = arguments.length <= 1 || arguments[1] === undefined ? {} : arguments[1];

  var _ref$iterations = _ref.iterations;
  var iterations = _ref$iterations === undefined ? getIterationsFromYear(getYear()) : _ref$iterations;
  var _ref$algorithm = _ref.algorithm;
  var algorithm = _ref$algorithm === undefined ? 'sha1' : _ref$algorithm;
  var _ref$saltSize = _ref.saltSize;
  var saltSize = _ref$saltSize === undefined ? SALT_SIZE : _ref$saltSize;
  var _ref$keyLength = _ref.keyLength;
  var keyLength = _ref$keyLength === undefined ? KEY_LENGTH : _ref$keyLength;

  if (!secret) throw new Error('invalid secret');
  return new Promise(function (resolve, reject) {
    salt(saltSize, function (error, salt) {
      if (error) return reject(new Error('Error hashing secret'));
      (0, _crypto.pbkdf2)(secret, salt, iterations, keyLength, algorithm, function (err, key) {
        if (err) return reject(new Error('Error hashing secret'));
        resolve(store(iterations, key, salt));
      });
    });
  });
}

/**
 * Verify a secret matches an existing hash
 * @param secret {string}
 * @param hash {string}
 * @param cb {Function}
 */

function verify(secret, hash) {
  var _ref2 = arguments.length <= 2 || arguments[2] === undefined ? {} : arguments[2];

  var _ref2$algorithm = _ref2.algorithm;
  var algorithm = _ref2$algorithm === undefined ? 'sha1' : _ref2$algorithm;

  var _hash$split = hash.split('.');

  var _hash$split2 = _slicedToArray(_hash$split, 3);

  var iterations = _hash$split2[0];
  var key = _hash$split2[1];
  var salt = _hash$split2[2];

  iterations = Number.parseInt(iterations, 16);
  key = (0, _urlsafeBase64.decode)(key);
  salt = (0, _urlsafeBase64.decode)(salt);

  return new Promise(function (resolve, reject) {
    (0, _crypto.pbkdf2)(secret, salt, iterations, key.length, algorithm, function (error, derivedKey) {
      if (error) return reject(new Error('Error verifying hash'));
      resolve((0, _bufferEqualConstantTime2['default'])(derivedKey, key));
    });
  });
}