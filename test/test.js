const { Builder, By, until } = require('selenium-webdriver');
const assert = require('assert');
const mocha = require('mocha');
const CryptoJS = require('crypto-js');

    
describe('Test Live Ciphers', function() {
  before(async function() {
    timeout = 5000;
    let firefox = function() {
      const firefox = require('selenium-webdriver/firefox');
      const options = new firefox.Options();
      options.setPreference('browser.helperApps.neverAsk.saveToDisk', 'application/json application/octet-stream');
      options.setPreference('browser.download.folderList', 2)
      options.setPreference('browser.download.dir', __dirname.slice(0, __dirname.lastIndexOf('/')) + '/temp');
      options.headless();
      return new Builder().forBrowser('firefox').setFirefoxOptions(options).build();
    }

    let chrome = function() {
      const chrome = require('selenium-webdriver/chrome');
      const options = new chrome.Options();
      options.headless();
      return new Builder().forBrowser('chrome').setChromeOptions(options).build();
    }
    driver = await firefox();
  });
  
  after(function() {
    driver.quit();
  });
  
  beforeEach(async function() {
    testSalt = 'qPvRmfao+sM98TG54Fb5KG=='
    testIterations = 500;
    testPassword = 'password';
    testPlaintext = 'Test text to encrypt';
    testPBKDF2 = 'S4or59NpqNjNbUSTmINRZhNrLp1JZJhT5opA9Ro42c0=';
    testPBKDF2Ciphertext = 'U2FsdGVkX1/fLRPxcWaNDMF7PLa+kUeVu4yAP8r8REHX2KgHVwda5SxE1/nA9vSC';
    testPasswordCiphertext = 'U2FsdGVkX18sVg3BwqaURV9IBhRm+tolhL/NUAdnmDWoFVVs9O23Hy1krb7TYl87';
    
    let localIndex = __dirname.slice(0, __dirname.lastIndexOf('/')) + '/index.html';
    await driver.get(`file:///${localIndex}`);
    await driver.wait(until.elementLocated(By.css('body')), timeout);
    body = await driver.findElement(By.css('body'));
    usePBKDF2 = await body.findElement(By.id('usePBKDF2'));
    saltInput = await body.findElement(By.id('saltInput'));
    iterationsInput = await body.findElement(By.id('iterationsInput'));
    pbkdf2Output = await body.findElement(By.id('pbkdf2Output'));
    password = await body.findElement(By.id('passwordInput'));
    plaintext = await body.findElement(By.id('plaintextInput'));
    ciphertext = await body.findElement(By.id('ciphertextInput'));
    prng = await body.findElement(By.id('prng'));
    
    invalidCiphertextError = '<Invalid Ciphertext>';
    passwordError = '<Encryption requires a password to be entered>';
    pbkdf2BlankError = '<PBKDF2 requires a password, salt and number of iterations>';
    pbkdf2InvalidError = '<PBKDF2 salt must be a Base64 value (A-Za-z/+) and iterations must be an integer (0-1000000000)>';
  });
  
  afterEach(async function() {
  });
  
  describe('Test Encryption', function() {
    it('should pass encrypt plaintext using AES with password', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await password.sendKeys(testPassword);
      await plaintext.sendKeys(testPlaintext);
      let testOutput = await ciphertext.getAttribute('value');
      testOutput = CryptoJS.AES.decrypt(testOutput, testPassword);
      testOutput = testOutput.toString(CryptoJS.enc.Utf8);
      assert.equal(testPlaintext, testOutput);
    })
    
    it('should pass encrypt plaintext using AES with pbkdf2', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(!usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await saltInput.sendKeys(testSalt);
      await iterationsInput.clear();
      await iterationsInput.sendKeys(testIterations);
      await password.sendKeys(testPassword);
      let key = await pbkdf2Output.getAttribute('value');
      await plaintext.sendKeys(testPlaintext);
      let testOutput = await ciphertext.getAttribute('value');
      testOutput = CryptoJS.AES.decrypt(testOutput, testPBKDF2);
      testOutput = testOutput.toString(CryptoJS.enc.Utf8);
      assert.equal(testPlaintext, testOutput);
    })
    
    it('should fail encrypt plaintext using AES with pbkdf2 and missing salt', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(!usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await iterationsInput.clear();
      await iterationsInput.sendKeys(testIterations);
      await password.sendKeys(testPassword);
      let error = await pbkdf2Output.getAttribute('placeholder');
      assert.equal(pbkdf2BlankError, error);
    })
    
    it('should fail encrypt plaintext using AES with pbkdf2 and missing iterations', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(!usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await saltInput.sendKeys(testSalt);
      await iterationsInput.clear();
      await password.sendKeys(testPassword);
      let error = await pbkdf2Output.getAttribute('placeholder');
      assert.equal(pbkdf2BlankError, error);
    })
    
    it('should fail encrypt plaintext using AES with pbkdf2 and missing password', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(!usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await saltInput.sendKeys(testSalt);
      await iterationsInput.clear();
      await iterationsInput.sendKeys(testIterations);
      let error = await pbkdf2Output.getAttribute('placeholder');
      assert.equal(pbkdf2BlankError, error);
    })
    
    it('should fail encrypt plaintext using AES with pbkdf2 and invalid salt', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(!usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await saltInput.sendKeys('!@#$%^&*()');
      await iterationsInput.clear();
      await iterationsInput.sendKeys(testIterations);
      await password.sendKeys(testPassword);
      let error = await pbkdf2Output.getAttribute('placeholder');
      assert.equal(pbkdf2InvalidError, error);
    })
    
    it('should fail encrypt plaintext using AES with pbkdf2 and invalid iterations', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(!usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await saltInput.sendKeys(testSalt);
      await iterationsInput.clear();
      await iterationsInput.sendKeys('-100');
      await password.sendKeys(testPassword);
      let error = await pbkdf2Output.getAttribute('placeholder');
      assert.equal(pbkdf2InvalidError, error);
    })
  });
  
  describe('Test Decryption', function() {
    it('should pass decrypt ciphertext using AES with password', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await password.sendKeys(testPassword);
    })
    
    it('should pass decrypt ciphertext using AES with pbkdf2', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(!usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await saltInput.sendKeys(testSalt);
      await iterationsInput.clear();
      await iterationsInput.sendKeys(testIterations);
      await password.sendKeys(testPassword);
      let key = await pbkdf2Output.getAttribute('value');
      await ciphertext.clear();  // Discard later.
      await ciphertext.sendKeys(testPBKDF2Ciphertext);
      let testOutput = await plaintext.getAttribute('value');
      assert.equal(testPlaintext, testOutput);
    })
    
    it('should pass decrypt ciphertext using AES with pbkdf2 entered for password', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await password.sendKeys(testPBKDF2);
      await ciphertext.clear();
      await ciphertext.sendKeys(testPBKDF2Ciphertext);
      let testOutput = await plaintext.getAttribute('value');
      assert.equal(testPlaintext, testOutput);
    })
    
    it('should fail decrypt ciphertext using AES with pbkdf2 and missing salt', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(!usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await iterationsInput.clear();
      await iterationsInput.sendKeys(testIterations);
      await password.sendKeys(testPassword);
      await ciphertext.sendKeys(testPBKDF2Ciphertext);
      let testOutput = await pbkdf2Output.getAttribute('placeholder');
      assert.equal(pbkdf2BlankError, testOutput);
    })
    
    it('should fail decrypt ciphertext using AES with pbkdf2 and missing iterations', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(!usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await saltInput.sendKeys(testSalt);
      await iterationsInput.clear();
      await password.sendKeys(testPassword);
      await ciphertext.sendKeys(testPBKDF2Ciphertext);
      let testOutput = await pbkdf2Output.getAttribute('placeholder');
      assert.equal(pbkdf2BlankError, testOutput);
    })
    
    it('should fail decrypt ciphertext using AES with pbkdf2 and missing password', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(!usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await saltInput.sendKeys(testSalt);
      await iterationsInput.clear();
      await iterationsInput.sendKeys(testIterations);
      await ciphertext.sendKeys(testPBKDF2Ciphertext);
      let testOutput = await pbkdf2Output.getAttribute('placeholder');
      assert.equal(pbkdf2BlankError, testOutput);
    })
    
    it('should fail decrypt ciphertext using AES with pbkdf2 and invalid salt', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(!usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await saltInput.sendKeys('!@#$%^&*()');
      await iterationsInput.clear();
      await iterationsInput.sendKeys(testIterations);
      await password.sendKeys(testPassword);
      await ciphertext.sendKeys(testPBKDF2Ciphertext);
      let testOutput = await pbkdf2Output.getAttribute('placeholder');
      assert.equal(pbkdf2InvalidError, testOutput);
    })
    
    it('should fail decrypt ciphertext using AES with pbkdf2 and invalid iterations', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(!usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await saltInput.sendKeys(testSalt);
      await iterationsInput.clear();
      await iterationsInput.sendKeys('-1');
      await password.sendKeys(testPassword);
      await ciphertext.sendKeys(testPBKDF2Ciphertext);
      let testOutput = await pbkdf2Output.getAttribute('placeholder');
      assert.equal(pbkdf2InvalidError, testOutput);
      
      await iterationsInput.clear();
      await iterationsInput.sendKeys('50001');
      await password.sendKeys(testPassword);
      await ciphertext.sendKeys(testPBKDF2Ciphertext);
      testOutput = await pbkdf2Output.getAttribute('placeholder');
      assert.equal(pbkdf2InvalidError, testOutput);
    })
    
    it('should fail decrypt ciphertext using AES with pbkdf2 and invalid password', async function() {
      let usePBKDF2Bool = await usePBKDF2.isSelected();
      if(!usePBKDF2Bool) {
        await usePBKDF2.click();
      }
      await saltInput.sendKeys(testSalt);
      await iterationsInput.clear();
      await iterationsInput.sendKeys(testIterations);
      await password.sendKeys('Invalid Password');
      await ciphertext.sendKeys(testPBKDF2Ciphertext);
      let testOutput = await plaintext.getAttribute('placeholder');
      assert.equal(invalidCiphertextError, testOutput);
    })
  });
});
