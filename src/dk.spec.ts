import * as dk from './dk'

describe('derived-key', () => {
  describe('store', () => {
    it('concatenates the variables with .', () => {
      expect(dk.store(5, 'hello', 'world')).toEqual('5.aGVsbG8.d29ybGQ')
    })
    it('encodes numbers as hexadecimal', () => {
      expect(dk.store(64e3, 'hello', 'world')).toEqual('fa00.aGVsbG8.d29ybGQ')
    })
  })
  describe('hash', () => {
    let hash = ''
    beforeEach(async () => {
      hash = await dk.hash('secret', { iterations: 1000 })
    })
    it('should take a secret string and return a hash', () => expect(typeof hash).toEqual('string'))
    it('should have the iterations stored on it', () => expect(parseInt(hash.split('.')[0], 16)).toEqual(1000))
    it('it should verify another secret matches a given hash', async () =>
      expect(await dk.verify('secret', hash)).toBeTruthy())
    it('should not match an incorrect secret', async () => expect(await dk.verify('Secret', hash)).toBeFalsy())
    it('should not match another hash (random salt)', async () => {
      const hash2 = await dk.hash('secret', { iterations: 1000 })
      expect(hash2).not.toEqual(hash)
    })
  })
})
