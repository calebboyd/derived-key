import { pbkdf2, randomBytes } from 'crypto'
import { encode, decode } from 'urlsafe-base64'
import slowEquals from 'buffer-equal-constant-time'

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
 * Start with 1000 iterations in y2k double every 2 years thereafter
 * https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
 * @param year {number}
 * @returns {number}
 */
export function getIterationsFromYear(year){
  const iterations = Math.floor(Math.pow(2, (year - 2000) / 2) * 1000)
  if(iterations > MAX_SAFE_INTEGER){
    return MAX_SAFE_INTEGER
  }
  return iterations
}

/**
 * Return a random salt made of <size> bytes
 * @param size {number} Number of bytes the salt should be
 * @param cb {Function} (err,salt)
 */
export function salt(size = SALT_SIZE, cb){
  randomBytes(Math.floor(size), cb)
}

/**
 * Format the three pieces of information into a string for storage
 * @param iterations {number}
 * @param key {Buffer|string}
 * @param salt {Buffer|string}
 * @returns {string}
 */
export function store(iterations, key, salt){
  return `${iterations.toString(16)}.${encode(key)}.${encode(salt)}`
}

/**
 * Create a hash from a secret
 * @param secret {string}
 * @param iterations {number}
 * @param cb {Function}
 */
export function hash(
  secret,
  {
    iterations = getIterationsFromYear(getYear()),
    algorithm = 'sha1',
    saltSize = SALT_SIZE,
    keyLength = KEY_LENGTH
  } = {}) {
  if (!secret) throw new Error('invalid secret')
  return new Promise((resolve, reject) => {
    salt(saltSize, (error, salt) => {
      if (error) return reject(new Error('Error hashing secret'))
      pbkdf2(secret, salt, iterations, keyLength, algorithm, (err, key) => {
        if (err) return reject(new Error('Error hashing secret'))
        resolve(store(iterations, key, salt))
      })
    })
  })
}

/**
 * Verify a secret matches an existing hash
 * @param secret {string}
 * @param hash {string}
 * @param cb {Function}
 */
export function verify(secret, hash, { algorithm = 'sha1'} = {}){
  let [iterations, key, salt] = hash.split('.')
  iterations = Number.parseInt(iterations, 16)
  key = decode(key)
  salt = decode(salt)

  return new Promise((resolve, reject) => {
    pbkdf2(secret, salt, iterations, key.length, algorithm, (error, derivedKey) => {
      if (error) return reject(new Error('Error verifying hash'))
      resolve(slowEquals(derivedKey, key))
    })
  })
}