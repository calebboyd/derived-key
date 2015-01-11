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
})



