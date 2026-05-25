# ECB_Brute_Force
ECB is a mode of AES that encrypts blocks of a set of bytes individually. This is ripe grounds for attackers to exploit this as the state of every block should affect the permuations of every other block (diffusion). Because of this lack of diffusion if you control arbitrary input before the target ciphertext you can loop bytes with a set padding
