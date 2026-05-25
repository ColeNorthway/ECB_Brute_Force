# ECB_Brute_Force
ECB is a mode of AES that encrypts blocks of a set of bytes individually. This is ripe grounds for attackers to exploit this as the state of every block should affect the permuations of every other block (diffusion). 

## Padding
Because of this lack of diffusion if you control arbitrary input before the target ciphertext you can exploit this mode of AES. First here is a rundown of padding, specifically PKCS#7.
  + Pads blocks to a multiple of 16 when used with ECB mode AES
  + The padding bytes are repeating hex labeled as the size of padding
    + 0x01 or 0x05,0x05,0x05,0x05,0x05
  + If the ciphertext is perfectly aligned it will pad a fresh block of 16 0x10 bytes

## Exploitation
Below is the full exploitation attack chain.
  + Get the length of the target cipher text by prepending incremental bytes until the block size changes
    + The length is the initial ciphertext size - bytes it took to change size
  + Because of that last point above, you can pad 0x10 until we get the first block matching the last block.
    + This is done to identify the size of each block, to confirm the target is using ECB mode AES encryption and to know the size of the initial payload.
  + Next prepend your byte and iterate all 256 options for that byte while comparing front to back of the ciphertext
  + If it is a match prepend to your plaintext
