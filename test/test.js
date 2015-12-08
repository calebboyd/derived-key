import { expect } from 'chai'
import * as dk from '../src/'

describe('derived-key', () => {
  describe('getYear', () =>
    it('should return the current year', () =>
      expect(dk.getYear()).to.equal(2015)
    )
  )
  describe('getIterationsFromYear', () => {
    //https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
    it('should return the correct number of iterations', () => {
      expect(dk.getIterationsFromYear(0)).to.equal(0)
      //baseline 1000 in y2k
      expect(dk.getIterationsFromYear(2000)).to.equal(1000)
      expect(dk.getIterationsFromYear(2015)).to.equal(181019)
    })
    it('should max out in 2087', () => {
      expect(dk.getIterationsFromYear(2086)).to.be.lessThan(Math.pow(2,53)-1)
      expect(dk.getIterationsFromYear(2087)).to.equal(Math.pow(2,53)-1)
      expect(dk.getIterationsFromYear(2100)).to.equal(Math.pow(2,53)-1)
    })
  })
  describe('store', () => {
    it('concatenates the variables with .', () => {
      expect(dk.store(5,'hello','world')).to.equal('5.hello.world')
    })
    it('encodes numbers as hexadecimal', () => {
      expect(dk.store(64e3,'hello','world')).to.equal('fa00.hello.world')
    })
  })
  describe('hash', () => {
    let hash
    beforeEach(async () => hash = await dk.hash('secret', { iterations: 1000 }))
    it('should take a secret string and return a hash', () =>
      expect(hash).to.be.a('string')
    )
    it('should have the iterations stored on it', () =>
      expect(parseInt(hash.split('.')[0], 16)).to.equal(1000)
    )
    it('it should verify another secret matches a given hash', async () =>
      expect(await dk.verify('secret', hash)).to.be.true
    )
    it('should not match an incorrect secret', async () =>
      expect(await dk.verify('Secret', hash)).to.be.false
    )
    it('should not match another hash (random salt)', async () => {
      const hash2 = await dk.hash('secret', { iterations: 1000 })
      expect(hash2).to.not.equal(hash)
    })
  })
})



