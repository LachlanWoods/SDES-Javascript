# SDES-Javascript
An implementation of S-DES (Simplified Data Encryption Standard) in Javascript

S-DES is a simplified version of the DES block cipher, typically used for educational purposes.
S-DES uses 8 bit blocks, and a 10 bit shared key. Encryption and decryption is performed over two rounds. A key schedule is used to generate round keys for both rounds.

I created this project to teach myself the operations that are performed by block cipher, mainly the different permutations and substitutions that are used by many block ciphers.

All code related to S-DES can be found in SDES.js.
You can load up SDES.html in a web browser to view the result of each round of encryption (or decryption). Check the console for more detailed output.
