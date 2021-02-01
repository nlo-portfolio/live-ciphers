![Live Ciphers](https://raw.githubusercontent.com/nlo-portfolio/nlo-portfolio.github.io/master/style/images/programs/live-ciphers.png "Live Ciphers")

## Description ##

Live Ciphers is a cryptographic demonstration using CryptoJS. It allows users to encrypt and decrypt data in real-time using several different ciphers and includes PBKDF2 key derivation as well as a random number generator marquee.
<br><br>
[LIVE DEMO AVAILABLE](https://nlo-portfolio.github.io/live-ciphers "Live Ciphers Demo")

## Dependencies ##

None. Can be opened locally in a web browser (live-ciphers/index.html).<br>
Testing requires Selenium WebDriver and Node.js. Tests can be run using the provided docker-compose file.<br>
<br>
Browsers: Tested in Firefox v89+, Chromium v91+.

## Usage ##

A password must be entered to perform encryption/decryption. With a password entered, enter the data that needs to be encrypted/decrypted in the appropriate textarea.<br>
<br>
Docker:

```
docker-compose build
docker-compose run test
```
