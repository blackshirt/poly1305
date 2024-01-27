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

// block_size is internal size of Poly1305 block that operates on
const block_size = 16
// key_size is 256 bit one-time key size for input to Poly1305 mac, in bytes
const key_size = 32
// tag_size is size of output of Poly1305 result, in bytes
const tag_size = 16
// mask value for clamping r part
const rmask0 = u64(0x0FFFFFFC0FFFFFFF)
const rmask1 = u64(0x0FFFFFFC0FFFFFFC)

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
	buffer []u8 = []u8{len: poly1305.tag_size}
	offset int
}

fn new(key []u8) !&Poly1305 {
	if key.len != poly1305.key_size {
		return error('poly1305: bad key length')
	}
	// read r part from key and clamping it
	lo := binary.little_endian_u64(key[0..8])
	hi := binary.little_endian_u64(key[8..16])
	mut r := unsigned.uint128_new(lo, hi)
	clamp_r(mut r)

	// read s part from the rest bytes of key
	so := binary.little_endian_u64(key[16..24])
	si := binary.little_endian_u64(key[24..32])
	s := unsigned.uint128_new(so, si)

	ctx := &Poly1305{
		r: r
		s: s
	}
	return ctx
}

fn (mut ctx Poly1305) sum(mut out []u8) {
	if ctx.offset > 0 {
		update_generic(mut ctx, mut ctx.buffer[..ctx.offset])
	}
	finalize(mut out, mut ctx.acc, ctx.s)
}

fn (mut ctx Poly1305) write(buf []u8) !int {
	return error('not implemented')
}

fn (mut ctx Poly1305) update(mut p []u8) {
	if ctx.offset > 0 {
		n := copy(mut ctx.buffer[ctx.offset..], p)
		if ctx.offset + n < poly1305.tag_size {
			ctx.offset += n
			return
		}
		p = unsafe { p[n..] }
		ctx.offset = 0
		update_generic(mut ctx, mut ctx.buffer)
	}
	nn := p.len - p.len % poly1305.tag_size
	if nn > 0 {
		update_generic(mut ctx, mut p[..nn])
		p = unsafe { p[nn..] }
	}
	if p.len > 0 {
		ctx.offset += copy(mut ctx.buffer[ctx.offset..], p)
	}
}

// clamp_r does clearing some bits of r before being used.
// the spec says, the bits thats required to be clamped:
// odd index bytes, ie,  r[3], r[7], r[11], and r[15] are required to have their top four
// bits clear (be smaller than 16)
// and,
// even index bytes, ie,   r[4], r[8], and r[12] are required to have their bottom two bits
// clear (be divisible by 4)
fn clamp_r(mut r unsigned.Uint128) {
	r.lo &= poly1305.rmask0
	r.hi &= poly1305.rmask1
}

// we follow the go version
fn update_generic(mut ctx Poly1305, mut msg []u8) {
	// localize the thing
	mut h := ctx.acc
	r := ctx.r
	for msg.len > 0 {
		// h += m
		if msg.len >= poly1305.tag_size {
			// load 16 bytes msg
			mlo := binary.little_endian_u32(msg[0..8])
			mhi := binary.little_endian_u32(msg[8..16])
			m := unsigned.uint128_new(mlo, mhi)

			// The rfc requires us to set a bit just above the message size, ie,
			// add one bit beyond the number of octets.  For a 16-byte block,
			// this is equivalent to adding 2^128 to the number.
			// so we can just add 1 to the high part of accumulator
			h = h.add_128(unsigned.uint128_new(0, 1))

			// we adding 128 bits wide of msg to 256 bits wide of accumulator
			h = h.add_128(m)
			// updates msg slice
			msg = unsafe { msg[poly1305.block_size..] }
		} else {
			// If the msg block is not 16 bytes long (the last block), pad it with zeros.
			mut buf := []u8{len: poly1305.block_size}
			subtle.constant_time_copy(1, mut buf[..msg.len], msg)
			buf[msg.len] = u8(0x01)

			// Add this number to the accumulator, ie, h += m
			mo := binary.little_endian_u64(buf[0..8])
			mi := binary.little_endian_u64(buf[8..16])
			m := unsigned.uint128_new(mo, mi)
			h = h.add_128(m)
			// drains the msg, we have reached the last block
			msg = []u8{}
		}
		// multiplication of big number, h *= r, ie, Uint256 x Uint128
		// TODO: better way to do h = *r
		h = h.mul_128(r)
		// is this the right way to do reduction modulo p ?
		h = h % poly1305.p

		// update context state
		ctx.acc = h
	}
}

// select_64 returns x if v == 1 and y if v == 0, in constant time.
fn select_64(v u64, x u64, y u64) u64 {
	return ~(v - 1) & x | (v - 1) & y
}

// we adapt the go version
fn finalize(mut out []u8, mut h unsigned.Uint256, s unsigned.Uint128) {
	assert out.len == poly1305.tag_size
	// compute t = h - (2¹³⁰ - 5), and select h as the result if the
	// subtraction underflows, and t otherwise.
	// intrinsically, we rely on builtin `math.unsigned.Uint256` machinery
	// to do arithmetic.
	t, b := unsigned.sub_256(h, poly1305.p, u64(0))

	// h = h if h < p else h - p
	h.lo.lo = select_64(b, h.lo.lo, t.lo.lo)
	h.lo.hi = select_64(b, h.lo.hi, t.lo.hi)

	// Finally, we compute tag = h + s  mod  2¹²⁸
	// s is 128 bit of ctx.s, ie, Uint128
	h = h.add_128(s)

	// take only low 128 bit of h
	binary.little_endian_put_u64(mut out[0..8], h.lo.lo)
	binary.little_endian_put_u64(mut out[8..16], h.lo.hi)
}
