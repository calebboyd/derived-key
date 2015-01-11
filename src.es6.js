import { pbkdf2, randomBytes } from 'crypto';

//hash formatting
const SEPARATOR = '.'
const ENCODING = 'ascii'
const ITERATION_RADIX = 16

//hash length
const KEY_LENGTH = 32
const SALT_SIZE = 16
const MAX_SAFE_INTEGER = 9007199254740991

/**
 * Get the current year
 * @returns {number}
 */
export function getYear(){
  return (new Date).getFullYear()
}

/**
 * Get recommended iterations for pbkdf2 based on year
 * https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
 * @param year {number}
 * @returns {number}
 */
export function getIterationsFromYear(year){
  let iterations = Math.floor(Math.pow(2,(year - 2000)/2) * 1000)
  if(iterations > MAX_SAFE_INTEGER){
	  iterations = MAX_SAFE_INTEGER
  }
  return iterations
}

/**
 * Return a random salt made of <size> bytes
 * @param size {number} Number of bytes the salt should be
 * @param cb {Function} (err,salt)
 */
export function salt(size,cb){
  randomBytes(Math.floor(size),(err,rnd) =>
    cb(err || null, err ? void 0 : rnd))
}

/**
 * Format the three pieces of information into a string for storage
 * @param iterations {number}
 * @param key {Buffer}
 * @param salt {Buffer}
 * @returns {string}
 */
export function store(iterations,key,salt){
  return (iterations.toString(ITERATION_RADIX)
          + SEPARATOR + key.toString(ENCODING)
          + salt.toString(ENCODING))
}

/**
 * Create a hash from a secret
 * @param secret {string}
 * @param iterations {number}
 * @param cb {Function}
 */
export function hash(secret, iterations, cb){
  cb = cb || iterations
  iterations = iterations === cb ? getIterationsFromYear(getYear()) : iterations
  salt(SALT_SIZE,(err,salt) => err ? cb(err) :
    pbkdf2(secret, salt.toString(ENCODING), iterations, KEY_LENGTH,(err,key) =>
      cb(err || null, err ? void 0 : store(iterations,key,salt))))
}

/**
 * Compare two strings in constant time
 * //hapijs/cryptiles
 * @param a {string}
 * @param b {string}
 * @returns {boolean}
 */
export function constantTimeCompare(a, b) {

  if (typeof a !== 'string' || typeof b !== 'string') {
    return false
  }
  let mismatch = (a.length === b.length ? 0 : 1)
  if (mismatch) {
    b = a
  }

  for(var i = 0, il = a.length; i < il; ++i) {
    let ac = a.charCodeAt(i)
    let bc = b.charCodeAt(i)
    mismatch |= (ac ^ bc)
  }
  return mismatch === 0
}

/**
 * Verify a secret matches an existing hash
 * @param secret {string}
 * @param hash {string}
 * @param cb {Function}
 */
export function verify(secret,hash,cb){
  let salt = hash.substring(hash.length - SALT_SIZE, hash.length)
  let iterations = parseInt(hash.split(SEPARATOR)[0],ITERATION_RADIX)
  pbkdf2(secret,salt,iterations, KEY_LENGTH, (err,key) => cb(err || null, err ?
    void 0 : constantTimeCompare(hash,store(iterations,key,salt))))
}