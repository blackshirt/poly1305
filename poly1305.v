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

// p is 130 bit of Poly1305 constant prime, ie 2^130-5
// as defined in rfc, p = 3fffffffffffffffffffffffffffffffb
const p = [u64(0xFFFFFFFFFFFFFFFB), u64(0xFFFFFFFFFFFFFFFF), u64(0x0000000000000003)]

struct Poly1305 {
mut:
	// 32 bytes of key input is partitioned into two's 128 bit parts, r and s
	// where r is clamped before stored.
	r unsigned.Uint128
	s unsigned.Uint128
	// Poly1305 arithmatic accumulator
	acc [3]u64
	// buffer
	buffer []u8 = []u8{len: poly1305.block_size}
	offset int
	// flag thats tells should not be used
	done bool
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
	mut h0 := ctx.acc[0]
	mut h1 := ctx.acc[1]
	mut h2 := ctx.acc[2]
	r := ctx.r
	for msg.len > 0 {
		// carry
		mut c := u64(0)
		// h += m
		if msg.len >= poly1305.block_size {
			// load 16 bytes msg
			mlo := binary.little_endian_u32(msg[0..8])
			mhi := binary.little_endian_u32(msg[8..16])
			m := unsigned.uint128_new(mlo, mhi)

			// We add 128 bit msg with 64 bit from related accumulator
			// just use Uint128.overflowing_add_64(v u64) (Uint128, u64)
			h0, c = bits.add_64(h0, m.lo)
			h1, c = bits.add_64(h1, m.hi)
			// The rfc requires us to set a bit just above the message size, ie,
			// add one bit beyond the number of octets.  For a 16-byte block,
			// this is equivalent to adding 2^128 to the number.
			// so we can just add 1 to the high part of accumulator
			h2 += c + 1

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

			h0, c = bits.add_64(h0, m.lo)
			h1, c = bits.add_64(h1, m.hi)
			h2 += c
			// drains the msg, we have reached the last block
			msg = []u8{}
		}
		// multiplication of h and r, h *= r,
		// TODO: better way to do h *= r
		// struct Acc {
		//		low 	unsigned.Uint128
		//		hibit 	u8 	
		// }
		// 			h2		h1		h0		
		// 							r		// 128 bit
		// 	----------------------------x
		//			rh2	  	rh1		rh0 	// individual Uint128 product
		//  ----------------------------
		// 		rh2.hi	rh1.hi	rh0.hi
		//				rh2.lo	rh1.lo	rh0.lo
		//	----------------------------------
		rh0 := r.mul_64(h0) 
		rh1 := r.mul_64(h1)
		rh2 := r.mul_64(h2)

		if rh2.hi != 0 {
			panic("poly1305: unexpected overflow")
		}

		// propagates carry
		t0 := rh0.lo
		t1, c0 := bits.add_u64(rh1.lo, rh0.hi, 0)
		t2, _ := bits.add_u64(rh2.lo, rh1.hi, c0)
		

		// is this the right way to do reduction modulo p ?
		h = h % poly1305.p

		// update context state
		ctx.acc = h
	}
}

// Accumulator, basically its a similar to go, [3]u64
struct Acc {
mut:
	h [3]u64
}

// u128_new creates new Uint128 from 64x64 bit product of x*y
fn u128_new(x u64, y u64) unsigned.Uint128 {
	hi, lo := bits.mul_64(x, y)
	return unsigned.uint128_new(lo, hi)
}
			
fn (mut h Acc) mul_r(r unsigned.Uint128) {
	h0 := h.low.lo 
	h1 := h.low.hi
	h2 := h.high
	r0 := r.lo 
	r1 := r.hi 
	// 				h2		h1		h0
	//						r1 		r0
	//	-------------------------------x
	//		           h2r0	  h1r0	h0r0 // 128 bit product
	//         h2r1    h1r1   h0r1
	//  --------------------------------
	//         m3      m2     m1    m0      
	//   -------------------------------
	//   m3.hi     m2.hi     m1.hi  m0.hi
	//             m3.lo     m2.lo  m1.lo   m0.lo
	//  -----------------------------------------
	//      t4     t3         t2    t1      t0
	//  ------------------------------------------
	h0r0 := u128_new(h0, r0)
	h1r0 := u128_new(h1, r0)
	h2r0 := u128_new(h2, r0)
	h0r1 := u128_new(h0, r1)
	h1r1 := u128_new(h1, r1)
	h2r1 := u128_new(h2, r1)

	m0 := h020 
	m1, c0 := unsigned.add_128(h1r0, h1r1, 0) // (Uint128, u64)
	m2, c1 := unsigned.add_128(h2r0, h1r1, c0)
	m3, c2 := h2r1.overflowing_add_64(c1)
	// should we check for c2 carry ?
	if c2 != 0 {
		panic("poly1305: overflow")
	}

	t0 := m0.lo
	t1, c3 := bits.add_64(m0.hi, m1.lo, 0)
	t2, c4 := bits.add_64(m1.hi, m2.lo, c3)
	
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
