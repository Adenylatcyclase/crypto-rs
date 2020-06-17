# What is this Project?
Currently this is just a learning experience for me by implementing various crypto functionalities.

# Intermediate Feature List
- [x] Sha1 -> [RFC3174](https://tools.ietf.org/html/rfc3174)
- [x] Sha2 (224 and 256) -> [RFC4634](https://tools.ietf.org/html/rfc4634)
- [x] Sha3 (384 and 512) -> [RFC4634](https://tools.ietf.org/html/rfc4634)
- [x] MD5 -> [RFC1321](https://tools.ietf.org/html/rfc1321)
- [ ] AES-128-cdc -> [Spec](https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf)
- - [x] AES-128 cipher works
- - [ ] AES-128 decipher works
- - [ ] cbc encrypt implementation
- - [ ] cbc decrypt implementation
- [ ] general fixes
- - [x] padding module
- - - [x] bit padding like in md5 and sha [RFC1321](http://www.faqs.org/rfcs/rfc1321.html)
- - - [x] pxcs#7 padding [RFC5652](https://tools.ietf.org/html/rfc5652#section-6.3)
- - [ ] Hash fixes
- - - [ ] hashes as simple methods
- - - [x] use bytes module for turning objects into &[u8]
- - - [ ] HashMessage object for api similar to pythons hashlib
- - [ ] AES fixes
- - - [x] misc functions like galois in separate modul
- - - [ ] parameterize functions properls and dont rely on fixed length arrays -> Result?
- [ ] PBKDF2 -> [RFC8018](https://tools.ietf.org/html/rfc8018)