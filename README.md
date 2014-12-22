coolview-java
=============

A small set of classes for easy use of crypto functions and setting up daemons.


**Crypto**
Easy access to byte array comparison/concatenation, Base64, AES, Hex, ModHex, Obfuscate, PBKDF, RSA key generation, various certificate methods, Message Digest, HMAC, Random and string splitting.

**Alice** & **Bob** (+ Main)
Example implementation of E-OTP, see [here](https://defuse.ca/eotp.htm) for more information.

**AbstractServlet**
Simple base class with proper parameter reading.

**BasicSignalHandler**
Signal handling class. It's use depends on OS support for proper POSIX signal handling. Windows can only catch "CTRL-C", while Linux supports them all. Please note that support relies sun.misc.Signal & sun.misc.SignalHandler.
