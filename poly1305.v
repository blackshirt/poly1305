// Copyright (c) 2022 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Poly1305 one time message authentication code (MAC)
module poly1305

import math
import math.unsigned 
import encoding.binary
import crypto.internal.subtle

pub const (
	// block_size is internal size of Poly1305 block that operates on
	block_size = 16
	// key_size is 256 bit one-time key size for input to Poly1305 mac, in bytes
	key_size   = 32
	// tag_size is size of output of Poly1305 result, in bytes
	tag_size   = 16
)

const rmask0 = 0x0FFFFFFC0FFFFFFF
const rmask1 = 0x0FFFFFFC0FFFFFFC

struct Poly1305 {
mut:
	// 32 bytes of key is splitted into two's of 128 bit parts, r and s
	// where r is clamped before stored to instance.
	r unsigned.Uint128 
	s unsigned.Uint128

	// accumulator
	h unsigned.Uint256 

	// buffer 
	buffer [tag_size]u8 
	offset int 
}

fn new(key []u8) !&Poly1305 {
	if key.len != key_size {
		return error("poly1305: bad key length")
	}
	// read r part from key and clamping it 
	lo := binary.little_endian_u32(key[0..8]) & rmask0
	hi := binary.little_endian_u32(key[8..16]) & rmask1 
	r := unsigned.uint128_new(lo, hi) 

	// read s part from the rest bytes of key 
	so := binary.little_endian_u32(key[16..24])
	si := binary.little_endian_u32(key[24..32])
	s := unsigned.uint128_new(so, si)

	p := &Poly1305{
		r: r 
		s: s 
	}
	return p 
}