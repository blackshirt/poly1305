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

// block_size is the internal size of the Poly1305 block that operates on
const block_size = 16
// key_size is a 256-bit one-time key size for input to Poly1305 mac in bytes.
const key_size = 32
// tag_size is the size of the output of the Poly1305 result, in bytes.
const tag_size = 16
// mask value for clamping low 64 bits of the r part, clearing 10 bits
const rmask0 = u64(0x0FFFFFFC0FFFFFFF)
// mask value for clamping high 64 bits of the r part, clearing 12 bits
const rmask1 = u64(0x0FFFFFFC0FFFFFFC)

// mask value for low 2 bits of u64 value
const mask_low2bits = u64(0x0000000000000003)
// mask value for high 62 bits of u64 value, u64(0xfffffffffffffffc)
const mask_high62bits = u64(0xfffffffffffffffc)

// p is 130 bit of Poly1305 constant prime, ie 2^130-5
// as defined in rfc, p = 3fffffffffffffffffffffffffffffffb
const p = [u64(0xFFFFFFFFFFFFFFFB), u64(0xFFFFFFFFFFFFFFFF), u64(0x0000000000000003)]

// Poly1305 mac instance
struct Poly1305 {
mut:
	// Poly1305 mac accepts 32 bytes (256 bits) of key input.
	// This key is partitioned into two's 128 bits parts, r and s
	// where r is clamped before stored and the s part is kept secret.
	r unsigned.Uint128
	s unsigned.Uint128
	// Poly1305 arithmatic accumulator
	h [3]u64
	// buffer
	buffer   []u8 = []u8{len: poly1305.block_size}
	leftover int
	// The done flag thats tells the instance should not be used again.
	// Its set to true after calling finish or reset on instance.
	done bool
}

// new creates a new Poly1305 instance from 32 bytes of key provided.
@[direct_array_access]
pub fn new(key []u8) !&Poly1305 {
	if key.len != poly1305.key_size {
		return error('poly1305: bad key length')
	}
	// Read the r part of the key and clamp it. Clamping was done by clearing
	// some bits of r before being used. The spec says the bits from 16 bytes of r,
	// that are required to be clamped are: some odd index bytes, i.e., r[3],
	// r[7], r[11], and r[15], are required to have their top four bits clear
	// (be smaller than 16), and some even index bytes, i.e., r[4], r[8], and r[12],
	// are required to have their bottom two bits clear (be divisible by 4),
	// totally clearing 22 bits. In 128-bit little-endian format, the clamping
	// mask value is 0x0ffffffc0ffffffc0ffffffc0fffffff.
	// See the rmask0 and rmask1 constants above.
	r := unsigned.Uint128{
		lo: binary.little_endian_u64(key[0..8]) & poly1305.rmask0
		hi: binary.little_endian_u64(key[8..16]) & poly1305.rmask1
	}

	// read s part from the rest bytes of key
	s := unsigned.Uint128{
		lo: binary.little_endian_u64(key[16..24])
		hi: binary.little_endian_u64(key[24..32])
	}

	ctx := &Poly1305{
		r: r
		s: s
	}
	return ctx
}

// reset zeroises Poly1305 context and makes it in unusable state.
// You should reinit the instance with the new key instead to make its usable again.
fn (mut po Poly1305) reset() {
	po.r = unsigned.uint128_zero
	po.s = unsigned.uint128_zero
	po h[0] = 0
	po.h[1] = 0
	po.h[2] = 0
	po.leftover = 0
	unsafe {
		po.buffer.reset()
	}
	// we set done to true, to prevent accidental calls 
	// to update/finish on instance.
	po.done = true
}

// reinit reinitializes Poly1305 instance by resetting internal fields, and 
// then init with the new key.
fn (mut po Poly1305) reinit(key []u8) ! {
	if key.len != key_size {
		return error("bad key size")
	}
	// first, we reset the context and than setup its
	po.reset()
	po.r = unsigned.Uint128{
		lo: binary.little_endian_u64(key[0..8]) & poly1305.rmask0
		hi: binary.little_endian_u64(key[8..16]) & poly1305.rmask1
	}
	po.s = unsigned.Uint128{
		lo: binary.little_endian_u64(key[16..24])
		hi: binary.little_endian_u64(key[24..32])
	}
	// we set po.done to false, to make its usable again.
	po.done = false
}
		
pub fn create_mac(mut out []u8, msg []u8, key []u8) ! {
	if out.len != poly1305.tag_size {
		return error('bad out tag_size')
	}
	mut po := new(key)!
	mut m := msg.clone()
	po.update_block(mut m)
	po.finish(mut out)
	// zeroise Poly1305 context
	po.reset()
}

pub fn verify(tag []u8, msg []u8, key []u8) bool {
	mut po := new(key) or { panic(err) }
	mut out := []u8{len: poly1305.tag_size}
	mut m := msg.clone()
	po.update_block(mut m)
	po.finish(mut out)
	return subtle.constant_time_compare(tag, out) == 1
}

pub fn (mut po Poly1305) finish(mut out []u8) {
	if po.done {
		panic("poly1305: has done, please reinit with the new key")
	}
	if po.leftover > 0 {
		update_generic(mut po, mut po.buffer[..po.leftover])
	}
	finalize(mut out, mut po.h, po.s)
	// we reset instance to make its in bad unusable state.
	po.reset()
}

// update updates internal of Poly1305 state by message. Internally, it clones the message
// and supplies it to the update_block method. See the `update_block` method for details.
pub fn (mut po Poly1305) update(msg []u8) {
	mut m := msg.clone()
	po.update_block(mut m)
}

// update_block updates the internals of Poly105 state by block of message. As a note,
// it accepts mutable message data for performance reasons by avoiding message
// clones and working on message slices directly.
pub fn (mut po Poly1305) update_block(mut msg []u8) {
	if po.done {
		panic("poly1305: has done, please reinit with the new key")
	}
	if po.leftover > 0 {
		n := copy(mut po.buffer[po.leftover..], msg)
		if po.leftover + n < poly1305.block_size {
			po.leftover += n
			return
		}
		msg = unsafe { msg[n..] }
		po.leftover = 0
		update_generic(mut po, mut po.buffer)
	}
	nn := msg.len - msg.len % poly1305.tag_size
	if nn > 0 {
		update_generic(mut po, mut msg[..nn])
		msg = unsafe { msg[nn..] }
	}
	if msg.len > 0 {
		po.leftover += copy(mut po.buffer[po.leftover..], msg)
	}
}

// update_generic updates internal state of Poly1305 instance with message msg
fn update_generic(mut po Poly1305, mut msg []u8) {
	// For correctness and clarity, we check whether r is properly clamped.
	if po.r.lo & u64(0xf0000003f0000000) != 0 {
		panic('poly1305: bad r.lo')
	}
	if po.r.hi & u64(0xf0000003f0000003) != 0 {
		panic('poly1305: bad r.hi')
	}
	// We need the accumulator to be in correctly reduced form to make sure it is not overflowing.
	if po.h[2] & poly1305.mask_high62bits != 0 {
		panic('poly1305: h need to be reduced')
	}
	// localize the thing
	mut h := [po.h[0], po.h[1], po.h[2]]!
	mut t := [4]u64{}
	for msg.len > 0 {
		// carry
		mut c := u64(0)
		// h += m
		if msg.len >= poly1305.block_size {
			// load 16 bytes msg
			mo := binary.little_endian_u64(msg[0..8])
			mi := binary.little_endian_u64(msg[8..16])

			// add msg block to accumulator, h += m
			h[0], c = bits.add_64(h[0], mo, 0)
			h[1], c = bits.add_64(h[1], mi, c)
			// The rfc requires us to set a bit just above the message size, ie,
			// add one bit beyond the number of octets.  For a 16-byte block,
			// this is equivalent to adding 2^128 to the number.
			// so we can just add 1 to the high part of accumulator
			h[2] += c + 1

			// updates msg slice
			msg = unsafe { msg[poly1305.block_size..] }
		} else {
			// If the msg block is not 16 bytes long (the last block), pad it with zeros.
			mut buf := []u8{len: poly1305.block_size}
			subtle.constant_time_copy(1, mut buf[..msg.len], msg)
			// Add one bit beyond the number of octets
			buf[msg.len] = u8(0x01)

			// Add this number to the accumulator, ie, h += m
			mo := binary.little_endian_u64(buf[0..8])
			mi := binary.little_endian_u64(buf[8..16])

			h[0], c = bits.add_64(h[0], mo, 0)
			h[1], c = bits.add_64(h[1], mi, c)
			h[2] += c
			// drains the msg, we have reached the last block
			msg = []u8{}
		}
		// perform h *= r and then reduce output by modulo p
		mul_h_by_r(mut t, mut h, po.r)
		squeeze(mut h, t)
	}
	// updates accumulator
	po.h[0] = h[0]
	po.h[1] = h[1]
	po.h[2] = h[2]
}

// finalize does final reduction of accumulator h, adds it with secret s,
// and then take 128 bit of h stored in out.
fn finalize(mut out []u8, mut h [3]u64, s unsigned.Uint128) {
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
	// s is 128 bit of po.s, ie, Uint128
	mut c := u64(0)
	h0, c = bits.add_64(h0, s.lo, 0)
	h1, _ = bits.add_64(h1, s.hi, c)

	// take only low 128 bit of h
	binary.little_endian_put_u64(mut out[0..8], h0)
	binary.little_endian_put_u64(mut out[8..16], h1)
}

// mul_h_by_r multiplies accumulator h by r and stores the result in four of 64 bit limbs in t
fn mul_h_by_r(mut t [4]u64, mut h [3]u64, r unsigned.Uint128) {
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
	h0r0 := u128_mul(h[0], r.lo)
	h1r0 := u128_mul(h[1], r.lo)
	h0r1 := u128_mul(h[0], r.hi)
	h1r1 := u128_mul(h[1], r.hi)

	// For h[2], it has been checked above; even though its value has to be at most 7 
	// (for marking h has been overflowing 130 bits), the product of h2 and r0/r1
	// would not go to overflow 64 bits (exactly, a maximum of 63 bits). 
	// Its likes in the go version; we can ignore that high part of the product,
	// ie, h2r0.hi and h2r1.hi is equal to zero, but we elevate check for this.
	h2r0 := u128_mul(h[2], r.lo)
	h2r1 := u128_mul(h[2], r.hi)

	// In properly clamped r, product of h*r would not exceed 128 bits because r0 and r1
	// are clamped with rmask0 and rmask1 above. Its addition also does not exceed 128 bits either.
	// So, in other words, it should be c0 = c1 = c2 = 0.
	m0 := h0r0
	m1, c0 := unsigned.add_128(h1r0, h0r1, 0)
	m2, c1 := unsigned.add_128(h2r0, h1r1, c0)
	m3, c2 := h2r1.overflowing_add_64(c1)
	// check for c2 overflow
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

	// updates 4 64-bit limbs
	t[0] = t0
	t[1] = t1
	t[2] = t2
	t[3] = t3
}

// squeeze reduces accumulator h by doing partial reduction module p
// where t is result of previous h*r from mul_h_by_r calls.
fn squeeze(mut h [3]u64, t [4]u64) {
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

	// updates h
	h[0] = h0
	h[1] = h1
	h[2] = h2
}

// u128_mul creates new Uint128 from 64x64 bit product of x*y
fn u128_mul(x u64, y u64) unsigned.Uint128 {
	hi, lo := bits.mul_64(x, y)
	return unsigned.uint128_new(lo, hi)
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

fn u128_add(x unsigned.Uint128, y unsigned.Uint128) unsigned.Uint128 {
	v, c := unsigned.add_128(x, y, 0)
	if c != 0 {
		panic('poly1305: unexpected overflow')
	}
	return v
}
