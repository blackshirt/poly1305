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
	
// mask for clamping r part
const rmask0 = 0x0FFFFFFC0FFFFFFF
const rmask1 = 0x0FFFFFFC0FFFFFFC

// p is Poly1305 constant prime, ie 2^130-5
// as defined in rfc, p = 3fffffffffffffffffffffffffffffffb
// we represent it in Uint256 base, 
// maybe bits of waste here, but we can optimize it later
const p = unsigned.Uint256{
		lo: unsigned.uint128_new(0xFFFFFFFFFFFFFFFB, 0xFFFFFFFFFFFFFFFF)
		hi: unsigned.uint128_new(0x0000000000000003, 0)
	}

struct Poly1305 {
mut:
	// 32 bytes of key input is partitioned into two's 128 bit parts, r and s
	// where r is clamped before stored.
	r unsigned.Uint128 
	s unsigned.Uint128

	// accumulator
	acc unsigned.Uint256 

	// buffer 
	buffer []u8 = []u8{len: tag_size}
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

// we follow the go version
fn update_generic(mut ctx Poly1305, mut msg []u8) {
	// localize the thing
	mut h := ctx.acc 
	r := ctx.r 
	for msg.len > 0 {
		// h += m 
		if len.msg >= tag_size {
			// load 16 bytes msg
			mlo := binary.little_endian_u32(msg[0..8])
			mhi := binary.little_endian_u32(msg[8..16])
			m := unsigned.uint128_new(mlo, mhi)
			
			// The rfc requires us to set a bit just above the message size, ie, 
			// add one bit beyond the number of octets.  For a 16-byte block,
      		// this is equivalent to adding 2^128 to the number.
			// so we can just add 1 to the high part of accumulator
			h = h.add_128(uint128_new(0, 1))

	  		// we adding 128 bits wide of msg to 256 bits wide of accumulator
			h = h.add_128(m)
			// updates msg slice 
			msg = unsafe { msg[tag_size..] }
		} else {
			// If the msg block is not 17 bytes long (the last block), pad it with zeros
			mut buf := []u8{len: tag_size}
			subtle.constant_time_copy(1, mut buf[..msg.len], msg)

			// Add this number to the accumulator, ie, h += m 
			mo := binary.little_endian_u32(buf[0..8])
			mi := binary.little_endian_u32(buf[8..16])
			m := unsigned.uint128_new(mo, mi)
			h = h.add_128(m)
			// drains the msg 
			msg = []u8{}
		}
		// multiplication of big number, h *= r, ie, Uint256 x Uint128
		h = h.mul_128(r)
		// reduction modulo p 
		h = h % p

		// update context state 
		ctx.acc = h
	}
}
