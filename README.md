# poly1305

Poly1305 is a one-time authenticator originally designed by D. J. Bernstein.
Poly1305 takes a 32-byte one-time key and a message and produces a
16-byte tag. It can be used to verify the data integrity and the authenticity of a message.

This module provide `poly1305` message authentication code (MAC) for V Language.