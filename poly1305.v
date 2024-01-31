// Copyright (c) 2022 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Poly1305 one time message authentication code (MAC)
module poly1305

import math
import math.bits
import math.unsigned
import encoding.binary
import crypto.internal.subtle

// block_size is internal size of Poly1305 block that operates on
const block_size = 16
// key_size is 256 bit one-time key size for input to Poly1305 mac, in bytes
const key_size = 32
// tag_size is size of output of Poly1305 result, in bytes
const tag_size = 16

// mask value for clamping r part, ie, 0x0ffffffc0ffffffc0ffffffc0fffffff
const rmask0 = u64(0x0FFFFFFC0FFFFFFF) // clears 10 bits

const rmask1 = u64(0x0FFFFFFC0FFFFFFC) // clears 12 bits

// mask value for low 2 bits of u64 value
const mask_low2bits = u64(0x0000000000000003)
// mask value for high 62 bit of u64 value
const mask_high62bits = u64(0xfffffffffffffffc)

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
	h Acc
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
	mut p := ctx
	if p.offset > 0 {
		update_generic(mut p, mut p.buffer[..p.offset])
	}
	finalize(mut out, mut ctx.h, p.s)
}

fn (mut ctx Poly1305) write(buf []u8) !int {
	return error('not implemented')
}

fn (mut ctx Poly1305) update(mut p []u8) {
	if ctx.offset > 0 {
		n := copy(mut ctx.buffer[ctx.offset..], p)
		if ctx.offset + n < poly1305.block_size {
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
// clear (be divisible by 4).
// in 128 bits little endian form, the mask is 0x0ffffffc0ffffffc0ffffffc0fffffff
fn clamp_r(mut r unsigned.Uint128) {
	r.lo &= poly1305.rmask0
	r.hi &= poly1305.rmask1
}

// we follow the go version
fn update_generic(mut ctx Poly1305, mut msg []u8) {
	// for correctness and clarity, we check whether r is properly clamped.
	// ie, r is masked by 0x0ffffffc0ffffffc0ffffffc0fffffff
	if ctx.r.lo & u64(0xf0000003f0000000) != 0 {
		panic('bad r.lo')
	}
	if ctx.r.hi & u64(0xf0000003f0000003) != 0 {
		panic('bad r.hi')
	}

	// localize the thing
	mut h0 := ctx.h[0]
	mut h1 := ctx.h[1]
	mut h2 := ctx.h[2]
	r0 := ctx.r.lo
	r1 := ctx.r.hi
	// We need h to be in correctly reduced form to make sure h is not overflowing.
	if h2 & poly1305.mask_high62bits != 0 {
		panic('poly1305: h need to be reduced')
	}
	for msg.len > 0 {
		// carry
		mut c := u64(0)
		// h += m
		if msg.len >= poly1305.block_size {
			// load 16 bytes msg
			mlo := binary.little_endian_u32(msg[0..8])
			mhi := binary.little_endian_u32(msg[8..16])
			// m := unsigned.uint128_new(mlo, mhi)

			// We add 128 bit msg with 64 bit from related accumulator
			// just use Uint128.overflowing_add_64(v u64) (Uint128, u64)
			h0, c = bits.add_64(h0, mlo, 0)
			h1, c = bits.add_64(h1, mhi, c)
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
			// m := unsigned.uint128_new(mo, mi)

			h0, c = bits.add_64(h0, mo, 0)
			h1, c = bits.add_64(h1, mi, c)
			h2 += c
			// drains the msg, we have reached the last block
			msg = []u8{}
		}
		// multiply h by r

		// multiplication of h and r, ie, h*r
		// 							h2		h1		h0
		//									r1 		r0
		//	---------------------------------------------x
		//		           			h2r0	h1r0	h0r0 	// individual 128 bit product
		//         			h2r1	h1r1   	h0r1
		//  ---------------------------------------------
		//         			m3     	m2     	m1   	m0
		//   --------------------------------------------
		//   		m3.hi  	m2.hi   m1.hi  	m0.hi
		//             	   	m3.lo   m2.lo  	m1.lo   m0.lo
		//  ---------------------------------------------
		//      	t4     	t3     	t2     	t1     	t0
		//  --------------------------------------------
		// individual 128 bits product
		h0r0 := u128_mul(h0, r0)
		h1r0 := u128_mul(h1, r0)
		h0r1 := u128_mul(h0, r1)
		h1r1 := u128_mul(h1, r1)

		// For h2, it has been checked above; even though its value has to be at most 7 
		// (for marking h has been overflowing 130 bits), the product of h2 and r0/r1
		// would not go to overflow 64 bits (exactly, a maximum of 63 bits). 
		// Its likes in the go comment did, we can ignore that high part of the product,
		// ie, h2r0.hi and h2r1.hi is equal to zero, but we elevate check for this.
		h2r0 := u128_mul(h2, r0)
		h2r1 := u128_mul(h2, r1)

		// In properly clamped r, product of h*r would not exceed 128 bits because r0 and r1 of r
		// are masked with rmask0 and rmask1 above. Its addition of unsigned.Uint128 result
		// does not overflow 128 bit either. So, in other words, it should be c0 = c1 = c2 = 0.
		m0 := h0r0
		m1, c0 := unsigned.add_128(h1r0, h0r1, 0)
		m2, c1 := unsigned.add_128(h2r0, h1r1, c0)
		m3, c2 := h2r1.overflowing_add_64(c1)
		// for sake of clarity, we check c2 carry
		if c2 != 0 {
			panic('poly1305: overflow')
		}

		// Because the h2r1.hi part is a zero, the m3 product only depends on h2r1.lo.
		// This also means m3.hi is zero for a similar reason. Furthermore,
		// it tells us if the product doesn't have a fifth limb (t4), so we can ignore it.
		t0 := m0.lo
		mut t1, mut t2, mut t3 := u64(0), u64(0), u64(0)
		t1, c = bits.add_64(m0.hi, m1.lo, 0)
		t2, c = bits.add_64(m1.hi, m2.lo, c)
		t3, c = bits.add_64(m2.hi, m3.lo, c)
		if c != 0 {
			panic('poly1305: overflow')
		}

		// we return this 4 64-bit limbs
		//

		// squeeze
		h0, h1, h2 = t0, t1, t2 & poly1305.mask_low2bits // 130 bit of h
		mut cc := unsigned.uint128_new(t2 & poly1305.mask_high62bits, t3)

		h0, c = bits.add_64(h0, cc.lo, 0)
		h1, c = bits.add_64(h1, cc.hi, c)
		h2 += c

		cc = shift_right_by2(mut cc)

		h0, c = bits.add_64(h0, cc.lo, 0)
		h1, c = bits.add_64(h1, cc.hi, c)
		h2 += c
	}
	ctx.h[0] = h0
	ctx.h[1] = h1
	ctx.h[2] = h2
}

// The poly1305 arithmatic accumulator. Basically, it is the same as
// the accumulator on the poly1305 in the Golang version.
type Acc = [3]u64

// u128_mul creates new Uint128 from 64x64 bit product of x*y
fn u128_mul(x u64, y u64) unsigned.Uint128 {
	hi, lo := bits.mul_64(x, y)
	return unsigned.uint128_new(lo, hi)
}

// mul_by_r multiplies h by r
fn mul_h_by_r(mut h Acc, r unsigned.Uint128) [4]u64 {
	// for correctness and clarity, we check whether r is properly clamped.
	// ie, r is masked by 0x0ffffffc0ffffffc0ffffffc0fffffff
	if r.lo & u64(0xf0000003f0000000) != 0 {
		panic('bad r.lo')
	}
	if r.hi & u64(0xf0000003f0000003) != 0 {
		panic('bad r.hi')
	}

	// We need h to be in correctly reduced form to make sure h is not overflowing.
	if h[2] & poly1305.mask_high62bits != 0 {
		panic('poly1305: h need to be reduced')
	}
	r0 := r.lo
	r1 := r.hi
	// multiplication of h and r, ie, h*r
	// 							h2		h1		h0
	//									r1 		r0
	//	---------------------------------------------x
	//		           			h2r0	h1r0	h0r0 	// individual 128 bit product
	//         			h2r1	h1r1   	h0r1
	//  ---------------------------------------------
	//         			m3     	m2     	m1   	m0
	//   --------------------------------------------
	//   		m3.hi  	m2.hi   m1.hi  	m0.hi
	//             	   	m3.lo   m2.lo  	m1.lo   m0.lo
	//  ---------------------------------------------
	//      	t4     	t3     	t2     	t1     	t0
	//  --------------------------------------------
	// individual 128 bits product
	h0r0 := u128_mul(h[0], r0)
	h1r0 := u128_mul(h[1], r0)
	h0r1 := u128_mul(h[0], r1)
	h1r1 := u128_mul(h[1], r1)

	// For h[2], it has been checked above; even though its value has to be at most 7 
	// (for marking h has been overflowing 130 bits), the product of h2 and r0/r1
	// would not go to overflow 64 bits (exactly, a maximum of 63 bits). 
	// Its likes in the go comment did, we can ignore that high part of the product,
	// ie, h2r0.hi and h2r1.hi is equal to zero, but we elevate check for this.
	h2r0 := u128_mul(h[2], r0)
	h2r1 := u128_mul(h[2], r1)

	// In properly clamped r, product of h*r would not exceed 128 bits because r0 and r1 of r
	// are masked with rmask0 and rmask1 above. Its addition of unsigned.Uint128 result
	// does not overflow 128 bit either. So, in other words, it should be c0 = c1 = c2 = 0.
	m0 := h0r0
	m1, c0 := unsigned.add_128(h1r0, h0r1, 0)
	m2, c1 := unsigned.add_128(h2r0, h1r1, c0)
	m3, c2 := h2r1.overflowing_add_64(c1)
	// for sake of clarity, we check c2 carry
	if c2 != 0 {
		panic('poly1305: overflow')
	}

	// Because the h2r1.hi part is a zero, the m3 product only depends on h2r1.lo.
	// This also means m3.hi is zero for a similar reason. Furthermore,
	// it tells us if the product doesn't have a fifth limb (t4), so we can ignore it.
	t0 := m0.lo
	t1, c3 := bits.add_64(m0.hi, m1.lo, 0)
	t2, c4 := bits.add_64(m1.hi, m2.lo, c3)
	t3, c5 := bits.add_64(m2.hi, m3.lo, c4)
	if c5 != 0 {
		panic('poly1305: overflow')
	}

	// we return this 4 64-bit limbs
	return [t0, t1, t2, t3]!
}

// squeeze reduces accumulator by doing partial reduction module p
// where t is result of previous h*2 from h.mul_by_r
fn squeeze(t [4]u64) [3]u64 {
	// we follow the go version, by splitting from previous result in `t`
	// at the 2¹³⁰ mark into h and cc, the carry.
	// begin by splitting t
	mut h0, mut h1, mut h2 := t[0], t[1], t[2] & poly1305.mask_low2bits // 130 bit of h
	mut cc := unsigned.uint128_new(t[2] & poly1305.mask_high62bits, t[3])

	mut c := u64(0)
	h0, c = bits.add_64(h0, cc.lo, 0)
	h1, c = bits.add_64(h1, cc.hi, c)
	h2 += c

	cc = shift_right_by2(mut cc)

	h0, c = bits.add_64(h0, cc.lo, 0)
	h1, c = bits.add_64(h1, cc.hi, c)
	h2 += c

	return [h0, h1, h2]!
}

// we adapt the go version
fn finalize(mut out []u8, mut h Acc, s unsigned.Uint128) {
	assert out.len == poly1305.tag_size
	mut h0 := h[0]
	mut h1 := h[1]
	mut h2 := h[2]
	// compute t = h - p = h - (2¹³⁰ - 5), and select h as the result if the
	// subtraction underflows, and t otherwise.
	mut b := u64(0)
	mut t0, mut t1, mut t2 := u64(0), u64(0), u64(0)
	t0, b = bits.sub_64(h0, poly1305.p[0], 0)
	t1, b = bits.sub_64(h1, poly1305.p[1], b)
	t2, b = bits.sub_64(h2, poly1305.p[2], b)

	// h = h if h < p else h - p
	h0 = select_64(b, h0, t0)
	h1 = select_64(b, h1, t1)

	// Finally, we compute tag = h + s  mod  2¹²⁸
	// s is 128 bit of ctx.s, ie, Uint128
	mut c := u64(0)
	h0, c = bits.add_64(h0, s.lo, 0)
	h1, _ = bits.add_64(h1, s.hi, c)

	// take only low 128 bit of h
	binary.little_endian_put_u64(mut out[0..8], h0)
	binary.little_endian_put_u64(mut out[8..16], h1)
}

// constant_time_eq_64 returns 1 when x == y.
fn constant_time_eq_64(x u64, y u64) u64 {
	return ((x ^ y) - 1) >> 63
}

// select_64 returns x if v == 1 and y if v == 0, in constant time.
fn select_64(v u64, x u64, y u64) u64 {
	return ~(v - 1) & x | (v - 1) & y
}

fn shift_right_by2(mut a unsigned.Uint128) unsigned.Uint128 {
	a.lo = a.lo >> 2 | (a.hi & 3) << 62
	a.hi = a.hi >> 2
	return a
}
