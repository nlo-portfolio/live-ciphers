'use strict';


/**
 * This is the main JS module for live-ciphers and contains both the functions and listeners.
 * Live-Ciphers uses the Crypto-JS library for both encryption/decryption of text in real-time
 * as well as the generation of random characters.
 */
$(document).ready(function() {
  let prngInterval = 1000;
  let passwordInput = $('#passwordInput');
  let password = ''
  let enc_stream = '';
  let dec_stream = '';
  let prng = $('#prng');
  let plaintextInput = $('#plaintextInput');
  let ciphertextInput = $('#ciphertextInput');
  let cipherType = $('#cipherType');
  let usePBKDF2 = $('#usePBKDF2');
  let pbkdf2Row = $('#pbkdf2Row');
  let saltInput = $('#saltInput');
  let iterationsInput = $('#iterationsInput');
  let pbkdf2Output = $('#pbkdf2Output');
  let showPassword = $('#showPassword');
  let modeEncrypt = true;
  let randomString = getRandomChars(2500);  // Generate enough characters to fill div on zoom out.
  let invalidCiphertextError = '<Invalid Ciphertext>';
  let passwordError = '<Encryption requires a password to be entered>';
  let pbkdf2BlankError = '<PBKDF2 requires a password, salt and number of iterations>';
  let pbkdf2InvalidError = '<PBKDF2 salt must be a Base64 value (A-Za-z/+) and iterations must be an integer (0-1000000000)>';
  let plaintextPlaceholder = plaintextInput.attr('placeholder'); // 'Enter the plaintext to be encrypted here...';
  let ciphertextPlaceholder = ciphertextInput.attr('placeholder'); // 'Enter the encryption/decryption password here...';
  window.interval = setInterval(generatePRNG, prngInterval);

    
  /* Functions */

  /**
   * Encrypts the data in plaintext using the selected cipher type.
   * @param  {CryptoJS.Cipher}  cipher     Cipher to be used for encryption.
   * @param  {Boolean}          newPBKDF2  Whether to generate a new PBKDF2.
   */
  function encrypt(cipher, newPBKDF2 = true) {
    let key = getKey(newPBKDF2);
    if(!key || plaintextInput.val() == '') {
      return;
    };
    
    let encText = cipher.encrypt(plaintextInput.val(), key);
    plaintextInput.css('color', '#495057');
    ciphertextInput.val(encText.toString()).css('color', '#495057');
  }

  /**
   * Decrypts the data in ciphertext using the selected cipher type.
   * @param  {CryptoJS.Cipher}  cipher     Cipher to be used for decryption.
   * @param  {Boolean}          newPBKDF2  Whether to generate a new PBKDF2.
   */
  function decrypt(cipher, newPBKDF2 = true) {
    let key = getKey(newPBKDF2);
    if(!key || ciphertextInput.val() == '') {
      return;
    };
  
    let dec_stream = cipher.decrypt(ciphertextInput.val(), key);
    try {
      let decText = dec_stream.toString(CryptoJS.enc.Utf8);
      if (decText) {
        plaintextInput.val(decText.toString()).css('color', '#495057');
      } else {
        throw new Error('Malformed UTF-8 data');
      }
    } catch(error) {
      showError(invalidCiphertextError, plaintextInput);
    }
  }

  /*
   * Determines if a pbkdf2 or password is used for encryption.
   * Also generates a new pbkdf2 if necessary.
   * @param   {Boolean}  newPBKDF2  Whether a new key needs to be generated.
   * @return  {String}              The encryption key, or null if errors.
   */
  function getKey(newPBKDF2) {
    let key;
    let encText = ''
    if(usePBKDF2.is(':checked')) {
      if(saltInput.val() == '' || iterationsInput.val() == '' || passwordInput.val() == '') {
        showError(pbkdf2BlankError, pbkdf2Output);
        return;
      }
      
      if(!checkPBKDF2Params()) {
        showError(pbkdf2InvalidError, pbkdf2Output);
        return;
      }
      
      let salt = CryptoJS.enc.Base64.parse(saltInput.val());
      key = pbkdf2Output.val();
      if(newPBKDF2) {
        key = CryptoJS.enc.Base64.stringify(CryptoJS.PBKDF2(passwordInput.val(), salt, { keySize: 256 / 32, iterations: iterationsInput.val() }));
        pbkdf2Output.val(key).css('color', '#495057');
      }
    } else if(passwordInput.val() != '') {
      key = passwordInput.val();
    } else {
      showError(passwordError, ciphertextInput);
      return;
    }
    return key;
  }
  
  /**
   * Generate a new PBKDF2 key.
   * @param  {String}              password  Password used for generating PBKDF2.
   * @param  {CryptoJS.WordArray}  salt      Randomized value used for salt.
   * @param  {Integer}             iters     Iterations to be done.
   */
  function getPBKDF2(password, salt, iters) {
    return CryptoJS.enc.Base64.stringify(CryptoJS.PBKDF2(password, salt, { keySize: 512 / 32, iterations: iters }));
  }
  
  /*
   * Validates there is a base64 value for salt and an integer for iterations.
   * @return  {Boolean}  Whether all PBKDF2 parameters are present.
   */
  function checkPBKDF2Params() {
    if(saltInput.val().match(/^[A-Za-z0-9\/\+=]+$/) && iterationsInput.val().match(/^([1-4][0-9]{0,4}|[0-9]{0,4}|50000)$/)) {
      return true;
    } else {
      return false;
    }
  }

  /**
   * Generates random characters to display in the PRNG window.
   * @param   {int}     numChars  Number of random characters to generate.
   * @return  {String}            Randomly generated characters.
   */
  function getRandomChars(numChars) {
    let randomBytes = CryptoJS.lib.WordArray.random(numChars * 2);
    let randomChars = CryptoJS.enc.Base64.stringify(randomBytes).slice(0, numChars);
    return randomChars
  }
  
  /**
   * Display an error in the given element.
   * @param  {String}          msg   Message to display.
   * @param  {Jquery.Element}  elem  Element to display message.
   */
  function showError(message, element) {
    element.val('').attr('placeholder', message);
    element.addClass('placeholderRed');
  }
  
  /**
   * Reset the error placeholder in the given element.
   */
  function resetErrors() {
    plaintextInput.attr('placeholder', plaintextPlaceholder);
    plaintextInput.removeClass('placeholderRed');
    ciphertextInput.attr('placeholder', plaintextPlaceholder);
    ciphertextInput.removeClass('placeholderRed');
    pbkdf2Output.attr('placeholder', 'BASE64');
    pbkdf2Output.removeClass('placeholderRed');
  }

  /**
   * Shows and hides the PBKDF2 fields.
   */
  function setShowPBKDF2() {
    if(usePBKDF2.is(':checked')) {
      pbkdf2Row.show();
    } else {
      pbkdf2Row.hide();
    }
    refresh();
  }
  
  /**
   * Shows and hides the password field.
   */
  function setShowPassword() {
    if(showPassword.is(':checked')) {
      passwordInput.attr('type', 'text');
    } else {
      passwordInput.attr('type', 'password');
    }
  }

  /**
   * Validates the cipher type and returns the cipher function.
   * @return  {CryptoJS.Cipher}  Cipher used for encryption/decryption.
   */
  function getCipher() {
    let option = cipherType.val();
    return option == 'aes' ? CryptoJS.AES
         : option == 'des' ? CryptoJS.DES
         : option == '3des' ? CryptoJS.TripleDES
         : option == 'rabbit' ? CryptoJS.Rabbit
         : option == 'rc4' ? CryptoJS.RC4
         : option == 'rc4drop' ? CryptoJS.RC4Drop
         : CryptoJS.AES;
  }
  
  /**
   * Updates the scrolling PRNG window.
   */
  function generatePRNG() {
    randomString = getRandomChars(1) + randomString.slice(0, -1);
    prng.text(randomString.toString(CryptoJS.enc.Base64));      
  }
  
  /*
   * Refreshes the plaintext/ciphertext output windows with new data.
   * @param  {Boolean}  newPBKDF2  Whether to generate a new PBKDF2.
   */
  function refresh(newPBKDF2 = true) {
    if (modeEncrypt) {
      encrypt(getCipher(), newPBKDF2);
    } else {
      decrypt(getCipher(), newPBKDF2);
    }
  }


  /* Events */

  /**
   * Detect a change in cipher type, re-encrypt or re-decrypt text.
   */
  cipherType.change(function() {
    refresh(false);
  });
  
  /**
   * Detect a change in PBKDF2 salt, re-generate key.
   */
  saltInput.on('input', function() {
    refresh();
  });
  
  /**
   * Detect a change in PBKDF2 iterations, re-generate key.
   */
  iterationsInput.on('input', function() {
    refresh();
  });

  /**
   * Detect a change in the Use PBKDF2 option.
   */
  usePBKDF2.change(function() {
    setShowPBKDF2();
    refresh();
  });
  
  /**
   * Detect password change, re-encrypt text.
   */
  passwordInput.on('input', function() {
    refresh();
  });
 
  /**
   * Detect a change in the Show Password option.
   */
  showPassword.on('input', function() {
    setShowPassword();
  });

  /**
   * Stop the PRNG window scrolling while mouse is down (text is being selected).
   */
  $('#prng').mousedown(function(e) {
    clearInterval(window.interval);
  });
  
  /**
   * Detect plaintext input change, re-encrypt plaintext.
   */
  plaintextInput.on('input', function() {
    if(plaintextInput.val() == '') {
      ciphertextInput.val('');
      resetErrors();
    }
    modeEncrypt = true;
    encrypt(getCipher(), false);
  });

  /**
   * Detect ciphertext input change, re-decrypt ciphertext.
   */
  ciphertextInput.on('input', function() {
    if(ciphertextInput.val() == '') {
      plaintextInput.val('');
      resetErrors();
    }
    modeEncrypt = false;
    decrypt(getCipher(), false);
  });
  
  /**
   * Copy the selected text from the PRNG window to the clipboard and resume scrolling.
   */
  $('#prng').mouseup(function(e) {
    (function() {
      let $temp = $('<input>');
      $('body').append($temp);
      $temp.val(window.getSelection().toString()).select();
      document.execCommand('copy');
      $temp.remove();
    })
    window.interval = setInterval(generatePRNG, prngInterval);
  });
});
