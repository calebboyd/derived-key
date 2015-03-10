import { expect } from 'chai'
import * as dk from './src.es6.js'


describe('derived-key',() => {
  describe('getYear', () =>{
    it('should return the current year',() =>{
      expect(dk.getYear()).to.equal(2015)
    })
  })
  describe('getIterationsFromYear',() => {
    //https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
    it('should return the correct number of iterations',()=>{
      expect(dk.getIterationsFromYear(0)).to.equal(0)
      //baseline 1000 in y2k
      expect(dk.getIterationsFromYear(2000)).to.equal(1000)
      expect(dk.getIterationsFromYear(2002)).to.equal(2000)
      expect(dk.getIterationsFromYear(2015)).to.equal(181019)
    })
    it('should max out in 2087',()=>{
      expect(dk.getIterationsFromYear(2086)).to.be.lessThan(Math.pow(2,53)-1)
      expect(dk.getIterationsFromYear(2087)).to.equal(Math.pow(2,53)-1)
      expect(dk.getIterationsFromYear(2100)).to.equal(Math.pow(2,53)-1)
    })
  })
  describe('store',() =>{
    it('should take three variables and concatenate them',() => {
      expect(dk.store(5,'hello','world')).to.equal('5.helloworld')
      expect(dk.store(64e3,'hello','world')).to.equal('fa00.helloworld')
    })
    it('should encode buffers', () => {
      expect(dk.store(5,new Buffer('fa21','hex'),new Buffer('aa22','hex'))).to.equal('5.' + new Buffer('fa21aa22','hex').toString('ascii'))
    })
  })
  describe('hash', () => {
    let hash
    let hash1
    let hash2
    beforeEach(done =>{
      let d = 0
      dk.hash('secret',1000,(e,h)=>{
        hash = h;
        ++d === 2 && done()
      })
      dk.hash('secret',2000,(e,h)=>{
        hash2 = h;
        ++d === 2 && done()
      })
    })
    it('should take a secret string and return a hash', () => {
      expect(hash).to.be.a('string')
    })
    it('should have the iterations stored on it', () => {
      expect(parseInt(hash.split('.')[0],16)).to.equal(1000)
    })
    it('it should verify another secret matches a given hash', done =>{
      dk.verify('secret',hash, (e,y) => {
        expect(y).to.be.true
        done()
      })
    })
    it('should not match an incorrect secret', done => {
      dk.verify('Secret',hash, (e,y) => {
        expect(y).to.be.false
        done()
      })
    })
    it('should not match another hash with a different work level',() =>{
      //todo stub salt
      //copy hashA salt and iteration count
      let salta = hash.substring(hash.length - 16, hash.length);
      hash2 = hash.split('.')[0] + '.' + hash2.split('.')[1].substring(0,hash2.length - 16) + salta
      expect(hash2).to.not.equal(hash)
    })
  })
})



