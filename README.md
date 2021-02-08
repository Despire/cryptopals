# cryptopals

Cryptopals solution in Rust.

<b>Used as a exercise to familiarize myself with rust, meaning the code is garbage</b>

[Set1](https://cryptopals.com/sets/1)
------------------

| Problem                                                                  | Test         | Solved  |
|--------------------------------------------------------------------------|:------------:|:-------:|
| [Convert hex to base64][1]                                               |  [Tests][1]  |    ✓    |
| [Fixed XOR][1]                                                           |  [Tests][1]  |    ✓    |
| [Single-byte XOR cipher][1]                                              |  [Tests][1]  |    ✓    |
| [Detect single-character XOR][1]                                         |  [Tests][1]  |    ✓    |
| [Implement repeating-key XOR][1]                                         |  [Tests][1]  |    ✓    |
| [Break repeating-key XOR][1]                                             |  [Tests][1]  |    ✓    |
| [AES in ECB mode][7]                                                     |  [Tests][7]  |    ✓    |
| [Detect AES in ECB mode][1]                                              |  [Tests][1]  |    ✓    |

[Set2](https://cryptopals.com/sets/2)
------------------

| Problem                                                                  | Test         | Solved  |
|--------------------------------------------------------------------------|:------------:|:-------:|
| [Implement PKCS#7 padding][5]                                            |  [Tests][5]  |    ✓    |
| [Implement CBC mode][6]                                                  |  [Tests][6]  |    ✓    |
| [An ECB/CBC detection oracle][2]                                         |  [Tests][2]  |    ✓    |
| [Byte-at-a-time ECB decryption (Simple)][2]                              |  [Tests][2]  |    ✓    |
| [ECB cut-and-paste][2]                                                   |  [Tests][2]  |    ✓    |
| [Byte-at-a-time ECB decryption (Harder)][2]                              |  [Tests][2]  |    ✓    |
| [PKCS#7 padding validation][5]                                           |  [Tests][5]  |    ✓    |
| [CBC bitflipping attacks][2]                                             |  [Tests][2]  |    ✓    |

[Set3](https://cryptopals.com/sets/3)
------------------

| Problem                                                                  | Test         | Solved  |
|--------------------------------------------------------------------------|:------------:|:-------:|
| [The CBC padding oracle][3]                                              |  [Tests][3]  |    ✓    |
| [Implement CTR, the stream cipher mode][8]                               |  [Tests][8]  |    ✓    |
| [Break fixed-nonce CTR mode using substitutions][3]                      |  [Tests][3]  |    ✓    |
| [Break fixed-nonce CTR statistically][3]                                 |  [Tests][3]  |    ✓    |
| [Implement the MT19937 Mersenne Twister RNG][9]                          |  [Tests][9]  |    ✓    |
| [Crack an MT19937 seed][3]                                               |  [Tests][3]  |    ✓    |
| [Clone an MT19937 RNG from its output][9]                                |  [Tests][9]  |    ✓    |
| [Create the MT19937 stream cipher and break it][10]                      |  [Tests][10] |    ✓    |

[Set4](https://cryptopals.com/sets/4)
------------------

| Problem                                                                  | Test         | Solved  |
|--------------------------------------------------------------------------|:------------:|:-------:|
| [Break "random access read/write" AES CTR][4]                            |  [Tests][4]  |    ✓    |
| [CTR bitflipping][4]                                                     |  [Tests][4]  |    ✓    |
| [Recover the key from CBC with IV=Key][4]                                |  [Tests][4]  |    ✓    |
| [Implement a SHA-1 keyed MAC][11]                                        |  [Tests][11] |    ✓    |
| [Break a SHA-1 keyed MAC using length extension][4]                      |  [Tests][4]  |    ✓    |
| Break an MD4 keyed MAC using length extension                            |  Tests       |    x    |
| [Implement and break HMAC-SHA1 with an artificial timing leak][12]       |  [Tests][12] |    ✓    |
| Break HMAC-SHA1 with a slightly less artificial timing leak              |  Tests       |    x    |

[Set5](https://cryptopals.com/sets/5)
------------------

| Problem                                                                  | Test         | Solved  |
|--------------------------------------------------------------------------|:------------:|:-------:|
| [Implement Diffie-Hellman][0]                                            |  [Tests][0]  |    ✓    |
| [MITM attack on Diffie-Hellman with parameter injection][0]              |  [Tests][0]  |    ✓    |
| DH with negotiated groups, and break with malicious "g" parameters       |  Tests       |    x    |
| Implement Secure Remote Password (SRP)                                   |  Tests       |    x    |
| Break SRP with a zero key                                                |  Tests       |    x    |
| Offline dictionary attack on simplified SRP                              |  Tests       |    x    |
| Implement RSA                                                            |  Tests       |    x    |
| Implement an E=3 RSA Broadcast attack                                    |  Tests       |    x    |


[0]: src/set5.rs
[1]: src/set1.rs
[2]: src/set2.rs
[3]: src/set3.rs
[4]: src/set4.rs


[5]: src/padding.rs
[6]: src/aes_cbc.rs
[7]: src/aes_ecb.rs
[8]: src/aes_ctr.rs
[9]: src/mt19937.rs
[10]: src/mt_19937_cipher.rs
[11]: src/sha1.rs
[12]: src/hmac_server.rs