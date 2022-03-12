# poly1305

Poly1305 is a one-time authenticator originally designed by D. J. Bernstein.
Poly1305 takes a 32-byte one-time key and a message and produces a
16-byte tag. It can be used to verify the data integrity and the authenticity of a message.

This module provide `poly1305` message authentication code (MAC) for V Language.
As a note,  <b>a key must only be used for a single message</b>. Authenticating two different
messages with the same key allows an attacker to forge authenticators for other
messages with the same key.


## Installation

You can install this module from github.

```bash
v install https://github.com/blackshirt/poly1305
```

## Usage

1. Provide your secret keys with length 32 bytes, you can generate its randomly from `crypto.rand`
   or you can use `chacha20.otk_key_gen()` for generating one-time key intended for poly1305 keygen.
   If you want to use `chacha20.otk_key_gen()` function, you should install `chacha20` module to your path. 
   Its available at [chacha20](https://github.com/blackshirt/chacha20) 

2. If you would use `chacha20.otk_key_gen` provide its with nonce bytes, with length 12 or 24 bytes.
3. And then generates one-time key with `chacha20.otk_key_gen`.
4. Create Poly1305 mac instance with generated one-time key. If you are not going to use `chacha20.otk_key_gen` to generate key, make sure your key random enought to create poly1305 (feeds it with `crypto.rand`)
5. feeds your poly1305 instance with messages you want to be authenticated by calling `write` method.
6. And then, call finalize to produce your 16 byte tag associated with your messages. 

```V
module main 

import crypto.rand 
import blackshirt.chacha20

fn main() {
    // messages to auth
    msg := 'Hello my Girls.....!!'.bytes()

    // provides key with length 32 bytes
    key := rand.read(32) ?
    
    // provides your nonce with length 12 or 24 bytes
    nonce := rand.read(12) ?
    
    // and then create one-time key for poly1305
    otk := chacha20.otk_key_gen(key, nonce)

    // create new poly305 mac
    mut poly := poly1305.new_with_key(otk) ?

    // or if you dont want using `chacha20.otk_key_gen`, you can directly 
    // using key to instantiate poly1305 mac
    // mut poly := poly1305.new_with_key(key) ?

    // write message to mac
    poly.write(msg)

    // and then call finalize to produce 16 byte tag
    tag := poly.finalize()

}



```

## License
[MIT](https://choosealicense.com/licenses/mit/)