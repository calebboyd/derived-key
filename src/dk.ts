import { pbkdf2, randomBytes, timingSafeEqual } from 'crypto'
import { base64urlDecode as decode, base64urlEncode as encode } from '@hapi/b64'

//hash length
const KEY_LENGTH = 128
const SALT_SIZE = 32

/**
 * Return a random salt made of <size> bytes
 * @param size {number} Number of bytes the salt should be
 * @param cb {Function} (err,salt)
 */
export function salt(size = SALT_SIZE, cb: (err: Error | null, salt: Buffer) => void): void {
  randomBytes(Math.floor(size), cb)
}

/**
 * Format the three pieces of information into a string for storage
 * @param iterations {number}
 * @param key {Buffer|string}
 * @param salt {Buffer|string}
 * @returns {string}
 */
export function store(iterations: number, key: string | Buffer, salt: string | Buffer): string {
  return `${iterations.toString(16)}.${encode(key, 'utf-8')}.${encode(salt, 'utf-8')}`
}

/**
 * Create a hash from a secret
 * @param secret {string}
 * @param iterations {number}
 * @param cb {Function}
 */
export function hash(
  secret: string,
  { iterations = 100000, algorithm = 'sha256', saltSize = SALT_SIZE, keyLength = KEY_LENGTH } = {}
): Promise<string> {
  if (!secret) return Promise.reject(new Error('invalid secret'))
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
 * @param secret
 * @param hash
 * @returns
 */
export function verify(secret: string, hash: string, { algorithm = 'sha256' } = {}): Promise<boolean> {
  const [iterations, key, salt] = hash.split('.'),
    iterationCount = Number.parseInt(iterations, 16),
    decodedKey = decode(key, 'buffer'),
    decodedSalt = decode(salt, 'buffer')

  return new Promise((resolve, reject) => {
    pbkdf2(secret, decodedSalt, iterationCount, decodedKey.length, algorithm, (error, derivedKey) => {
      if (error) return reject(new Error('Error verifying hash'))
      resolve(timingSafeEqual(derivedKey, decodedKey))
    })
  })
}
