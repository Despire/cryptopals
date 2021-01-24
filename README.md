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


[1]: src/set1.rs
[2]: src/set2.rs
[3]: src/set3.rs
[4]: src/set4.rs


[5]: src/padding.rs
[6]: src/aes_cbc.rs
[7]: src/aes_ecb.rs