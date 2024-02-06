// Copyright (c) 2022 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Poly1305 one-time message authentication code (MAC) module
module poly1305

import math
import math.bits
import math.unsigned
import encoding.binary
import crypto.internal.subtle

// Constant defined in this module
// -------------------------------
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
// mask value for high 62 bits of u64 value
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
	h Uint192
	// buffer
	buffer   []u8 = []u8{len: poly1305.block_size}
	leftover int
	// The done flag tells us if the instance should not be used again.
	// It's set to true after calling finish or reset on the instance.
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

// reset zeroizes the Poly1305 instance and makes it in an unusable state.
// You should reinit the instance with the new key instead to make it usable again.
fn (mut po Poly1305) reset() {
	po.r = unsigned.uint128_zero
	po.s = unsigned.uint128_zero
	po.h = uint192_zero
	po.leftover = 0
	unsafe {
		po.buffer.reset()
	}
	// We set the done flag to true to prevent accidental calls
	// to update or finish methods on the instance.
	po.done = true
}

// reinit reinitializes Poly1305 instance by resetting internal fields, and
// then reinit instance with the new key.
pub fn (mut po Poly1305) reinit(key []u8) {
	if key.len != poly1305.key_size {
		panic('bad key size')
	}
	// first, we reset the instance and than setup its again
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

// create_tag generates 16 byte one-time message authenticator code (mac) stored inside out.
// Its accepts message bytes to be authenticated and the 32 bytes of the key.
// This is an oneshot function to create a tag and reset internal state after the call.
// For incremental updates, use the method based on Poly1305 instance.
pub fn create_tag(mut out []u8, msg []u8, key []u8) ! {
	if out.len != poly1305.tag_size {
		return error('bad out tag_size')
	}
	mut po := new(key)!
	mut m := msg.clone()
	po.update_block(mut m)
	po.finish(mut out)
	// zeroise Poly1305 fields
	po.reset()
}

// verify_tag verifies the message authentication code in the tag from the message msg
// compared to the mac from the calculated results with input message and key.
// Its return true if two tag is matching, and false otherwise.
pub fn verify_tag(tag []u8, msg []u8, key []u8) bool {
	mut po := new(key) or { panic(err) }
	mut out := []u8{len: poly1305.tag_size}
	mut m := msg.clone()
	po.update_block(mut m)
	po.finish(mut out)
	return subtle.constant_time_compare(tag, out) == 1
}

// Finish finalizes the message authentication code computation and stores the result in out.
// After calls this method, don't use the instance anymore to do most anything, but,
// you should reinitialize the instance with the new key with reinit method instead.
pub fn (mut po Poly1305) finish(mut out []u8) {
	if po.done {
		panic('poly1305: has done, please reinit with the new key')
	}
	if po.leftover > 0 {
		update_generic(mut po, mut po.buffer[..po.leftover])
	}
	finalize(mut out, mut po.h, po.s)
	// we reset instance to make its in bad unusable state.
	po.reset()
}

// verify does verify mac code is a valid and authenticated for message msg.
pub fn (mut po Poly1305) verify(mac []u8, msg []u8) bool {
	mut out := []u8{len: poly1305.tag_size}
	po.update(msg)
	po.finish(mut out)
	return subtle.constant_time_compare(mac, out) == 1
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
	if msg.len == 0 {
		return
	}
	if po.done {
		panic('poly1305: has done, please reinit with the new key')
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

// update_generic updates internal state of Poly1305 instance with message msg.
fn update_generic(mut po Poly1305, mut msg []u8) {
	// For correctness and clarity, we check whether r is properly clamped.
	if po.r.lo & u64(0xf0000003f0000000) != 0 && po.r.hi & u64(0xf0000003f0000003) != 0 {
		panic('poly1305: bad unclamped of r')
	}
	// We need the accumulator to be in correctly reduced form to make sure it is not overflowing.
	// mask with upper 61 bits (for > 130 bits) value
	if po.h.hi & u64(0xfffffffffffffff8) != 0 {
		panic('poly1305: h need to be reduced')
	}
	// localize the thing
	mut h := po.h
	mut t := [4]u64{}
	for msg.len > 0 {
		// carry
		mut c := u64(0)
		// h += m
		if msg.len >= poly1305.block_size {
			// load 16 bytes msg to the 128 bits of Uint128 
			m := unsigned.Uint128{
				lo: binary.little_endian_u64(msg[0..8])
				hi: binary.little_endian_u64(msg[8..16])
			}
			// add msg block to accumulator, h += m
			h, c = h.add_128_checked(m, 0)
			// The rfc requires us to set a bit just above the message size, ie,
			// add one bit beyond the number of octets.  For a 16-byte block,
			// this is equivalent to adding 2^128 to the number.
			// so we can just add 1 to the high part of accumulator (h.hi += 1)
			h.hi, c = bits.add_64(h.hi, 1, c)
			if c != 0 {
				panic('something bad')
			}

			// updates msg slice
			msg = unsafe { msg[poly1305.block_size..] }
		} else {
			// If the msg block is not 16 bytes long (the last block), pad it with zeros.
			mut buf := []u8{len: poly1305.block_size}
			subtle.constant_time_copy(1, mut buf[..msg.len], msg)
			// Add one bit beyond the number of octets
			buf[msg.len] = u8(0x01)

			// loads 16 bytes of message
			m := unsigned.Uint128{
				lo: binary.little_endian_u64(buf[0..8])
				hi: binary.little_endian_u64(buf[8..16])
			}
			// Add this number to the accumulator, ie, h += m
			h, c = h.add_128_checked(m, 0)
			h.hi, c = bits.add_64(h.hi, 0, c)
			if c != 0 {
				panic('something bad')
			}

			// drains the msg, we have reached the last block
			msg = []u8{}
		}
		// perform h *= r and then reduce output by modulo p
		mul_h_by_r(mut t, mut h, po.r)
		squeeze(mut h, t)
	}
	// updates accumulator
	po.h.lo = h.lo
	po.h.mi = h.mi
	po.h.hi = h.hi
}

// finalize does final reduction of accumulator h, adds it with secret s,
// and then take 128 bit of h stored in out.
fn finalize(mut out []u8, mut ac Uint192, s unsigned.Uint128) {
	assert out.len == poly1305.tag_size
	mut h := ac
	// compute t = h - p = h - (2¹³⁰ - 5), and select h as the result if the
	// subtraction underflows, and t otherwise.
	mut b := u64(0)
	mut t0, mut t1, mut t2 := u64(0), u64(0), u64(0)
	t0, b = bits.sub_64(h.lo, poly1305.p[0], 0)
	t1, b = bits.sub_64(h.mi, poly1305.p[1], b)
	t2, b = bits.sub_64(h.hi, poly1305.p[2], b)

	// h = h if h < p else h - p
	h.lo = select_64(b, h.lo, t0)
	h.mi = select_64(b, h.mi, t1)

	// Finally, we compute tag = h + s  mod  2¹²⁸
	// s is 128 bit of po.s, ie, Uint128
	mut c := u64(0)
	h.lo, c = bits.add_64(h.lo, s.lo, 0)
	h.mi, _ = bits.add_64(h.mi, s.hi, c)

	// take only low 128 bit of h
	binary.little_endian_put_u64(mut out[0..8], h.lo)
	binary.little_endian_put_u64(mut out[8..16], h.mi)
}

// mul_h_by_r multiplies accumulator h by r and stores the result in four of 64 bit limbs in t
fn mul_h_by_r(mut t [4]u64, mut h Uint192, r unsigned.Uint128) {
	// for multiplication of accumulator by r, we use custom allocator functionality defined as Uint192.
	// see custom.v for more detail.
	// Let's multiply h by r, h *= r, we stores the result on raw 320 bits of xh and hb
	// see mul_128_checked on custom.v for detail of logic used.
	xh, hb := h.mul_128_checked(r)

	// For h[2], it has been checked above; even though its value has to be at most 7 
	// (for marking h has been overflowing 130 bits), the product of h2 and r0/r1
	// would not go to overflow 64 bits (exactly, a maximum of 63 bits). 
	// Its likes in the go version; we can ignore that high part of the product,
	// ie, h2r0.hi and h2r1.hi is equal to zero, but we elevate check for this.
	// In properly clamped r, product of h*r would not exceed 128 bits because r0 and r1
	// are clamped with rmask0 and rmask1 above. Its addition also does not exceed 128 bits either.
	// So, in other words, it should be c0 = c1 = c2 = 0.
	// check for high bits of the result is not overflowing 256 bits, so we can ignore
	// high bit (hb.hi) of the Uint128 part.
	if hb.hi != 0 {
		panic('poly1305: unexpected overflow, non-null 5th limb')
	}

	// Because the h2r1.hi part is a zero, the m3 product only depends on h2r1.lo.
	// This also means m3.hi is zero for a similar reason. Furthermore,
	// it tells us if the product doesn't have a fifth limb (t4), so we can ignore it.

	// updates 5 64-bit limbs
	t[0] = xh.lo
	t[1] = xh.mi
	t[2] = xh.hi
	t[3] = hb.lo
	// we ignore 5th limb
}

// squeeze reduces accumulator h by doing partial reduction module p
// where t is result of previous h*r from mul_h_by_r calls.
fn squeeze(mut h Uint192, t [4]u64) {
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
	h.lo = h0
	h.mi = h1
	h.hi = h2
}
