MemCached Binary Protocol Revamp Parser

[Docs](https://valarauca.github.io/mbpr/mbpr/index.html)

The goal of this crate to start building a memcached rust client.

This crate implements an elementary level packet parser/encoder.
The custom semantics around individual opcode's extra fields is not handled
in this release. They will be in the future. 

This crate does NO verification data while encoding. So it on the library
implementary to ensure it follows the basic rules of MBPR for communicating
to a server. (Key <= 250 ASCII characters, Body <= 2MB, etc.)

####Import

```
[dependencies]
mbpr = "0.0.1"
```



