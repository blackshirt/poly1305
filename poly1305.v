// Copyright (c) 2022 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Poly1305 one time message authentication code (MAC)
module poly1305

import math
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

struct Poly1305 {
mut:
	// the key is partitioned into two parts, called "r" and "s"
	r [5]u32
	s [4]u32
	// accumulator h
	h [5]u32

	leftover int
	buffer   []u8

	done bool
}

// new_tag generates poly1305's tag authenticator for msg using a one-time key and
// return the 16-byte result. The key must be unique for each message, authenticating two
// different messages with the same key allows an attacker to forge messages at will.
pub fn new_tag(msg []u8, key []u8) []u8 {
	mut p := new_poly1305(key) or { panic(err.msg()) }
	p.input(msg)
	tag := p.result()
	return tag
}

// verify verifies mac is a valid authenticator for msg with the given key.
// its return true when mac is valid, and false otherwise.
pub fn verify(mac []u8, msg []u8, key []u8) bool {
	mut p := new_poly1305(key) or { panic(err.msg()) }
	p.input(msg)
	tag := p.result()
	return subtle.constant_time_compare(mac, tag) == 1
}

// new_poly1305 create new Poly1305 MAC instances and initializes it with the given key.
// Poly1305 MAC cannot be used like common hash, because using a poly1305 key twice breaks its security.
// Therefore feeding data to input to a running MAC after calling result causes it to panic.
pub fn new_poly1305(key []u8) !Poly1305 {
	if key.len != poly1305.key_size {
		return error('wrong key size provided')
	}
	mut p := Poly1305{
		buffer: []u8{len: poly1305.block_size}
	}
	// load the keys to two parts `r` and `s` and doing clamping
	// with r &= 0xffffffc0ffffffc0ffffffc0fffffff
	p.r[0] = (binary.little_endian_u32(key[0..4])) & 0x3ffffff
	p.r[1] = (binary.little_endian_u32(key[3..7]) >> 2) & 0x3ffff03
	p.r[2] = (binary.little_endian_u32(key[6..10]) >> 4) & 0x3ffc0ff
	p.r[3] = (binary.little_endian_u32(key[9..13]) >> 6) & 0x3f03fff
	p.r[4] = (binary.little_endian_u32(key[12..16]) >> 8) & 0x00fffff

	p.s[0] = binary.little_endian_u32(key[16..20])
	p.s[1] = binary.little_endian_u32(key[20..24])
	p.s[2] = binary.little_endian_u32(key[24..28])
	p.s[3] = binary.little_endian_u32(key[28..32])

	return p
}

// input feeds data into the Poly1305 internal state, its panic when
// called after calling result.
pub fn (mut p Poly1305) input(data []u8) {
	if p.done {
		panic(error('poly1305: feed input after result has been done'))
	}
	mut m := data.clone()

	if p.leftover > 0 {
		want := math.min(16 - p.leftover, m.len)
		mm := m[..want]
		// for (i, byte) in m.iter().cloned().enumerate().take(want) {
		for i, v in mm {
			p.buffer[p.leftover + i] = v
		}

		m = m[want..]
		p.leftover += want

		if p.leftover < poly1305.block_size {
			return
		}

		p.process_the_block(false)
		p.leftover = 0
	}

	for m.len >= poly1305.block_size {
		// TODO(tarcieri): avoid a copy here but do for now
		// because it simplifies constant-time assessment.
		subtle.constant_time_copy(1, mut p.buffer, m[..poly1305.block_size])
		p.process_the_block(false)
		m = m[poly1305.block_size..]
	}

	// p.buffer[..m.len].copy_from_slice(m);
	subtle.constant_time_copy(1, mut p.buffer[..m.len], m)
	p.leftover = m.len
}

//  input_padded input data to the Poly1305 with padded behaviour,
//  similar to the pad16() function described in RFC 8439 section 2.8.1:
//  [RFC8439](https://tools.ietf.org/html/rfc8439#section-2.8.1)
//
//  This is primarily useful for implementing ChaCHa20 family authenticated
//  encryption constructions.
pub fn (mut p Poly1305) input_padded(data []u8) {
	p.input(data)

	// Pad associated data with `\0` if it's unaligned with the block size
	unaligned_len := data.len % poly1305.block_size

	if unaligned_len != 0 {
		pad := []u8{len: poly1305.block_size}
		pad_len := poly1305.block_size - unaligned_len
		p.input(pad[..pad_len])
	}
}

// chained_input process input messages in a chained manner
pub fn (mut p Poly1305) chained_input(data []u8) Poly1305 {
	p.input(data)
	return p
}

// result calculates and output tag bytes with len `tag_size`
// and then `zeroize` all Poly1305's internal state.
pub fn (mut p Poly1305) result() []u8 {
	if p.leftover > 0 {
		p.buffer[p.leftover] = u8(0x01)

		for i in (p.leftover + 1) .. poly1305.block_size {
			p.buffer[i] = u8(0x00)
		}

		p.process_the_block(true)
	}

	// fully carry h
	mut h0 := p.h[0]
	mut h1 := p.h[1]
	mut h2 := p.h[2]
	mut h3 := p.h[3]
	mut h4 := p.h[4]

	mut c := u32(0)
	c = h1 >> 26
	h1 &= 0x3ffffff
	h2 += c

	c = h2 >> 26
	h2 &= 0x3ffffff
	h3 += c

	c = h3 >> 26
	h3 &= 0x3ffffff
	h4 += c

	c = h4 >> 26
	h4 &= 0x3ffffff
	h0 += c * 5

	c = h0 >> 26
	h0 &= 0x3ffffff
	h1 += c

	// compute h + -p
	mut g0 := h0 + 5 // h0.wrapping_add(5) //should do arithmatic without overflow
	c = g0 >> 26
	g0 &= 0x3ffffff

	mut g1 := h1 + c // h1.wrapping_add(c)
	c = g1 >> 26
	g1 &= 0x3ffffff

	mut g2 := h2 + c // h2.wrapping_add(c)
	c = g2 >> 26
	g2 &= 0x3ffffff

	mut g3 := h3 + c // h3.wrapping_add(c)
	c = g3 >> 26
	g3 &= 0x3ffffff

	mut g4 := h4 + c
	g4 -= (1 << 26) // h4.wrapping_add(c).wrapping_sub(1 << 26)

	// select h if h < p, or h + -p if h >= p
	mut mask := (g4 >> (32 - 1)) - 1 //.wrapping_sub(1)

	g0 &= mask
	g1 &= mask
	g2 &= mask
	g3 &= mask
	g4 &= mask

	mask = ~mask //!mask
	h0 = (h0 & mask) | g0
	h1 = (h1 & mask) | g1
	h2 = (h2 & mask) | g2
	h3 = (h3 & mask) | g3
	h4 = (h4 & mask) | g4

	// h = h % (2^128)
	h0 |= h1 << 26
	h1 = (h1 >> 6) | (h2 << 20)
	h2 = (h2 >> 12) | (h3 << 14)
	h3 = (h3 >> 18) | (h4 << 8)

	// h = mac = (h + s) % (2^128)
	mut f := u64(0)
	f = u64(h0) + u64(p.s[0])
	h0 = u32(f) // f as u32

	f = u64(h1) + u64(p.s[1]) + (f >> 32)
	h1 = u32(f) // f as u32

	f = u64(h2) + u64(p.s[2]) + (f >> 32)
	h2 = u32(f) // f as u32

	f = u64(h3) + u64(p.s[3]) + (f >> 32)
	h3 = u32(f) // f as u32

	mut tag := []u8{len: poly1305.tag_size}
	binary.little_endian_put_u32(mut tag[0..4], h0)
	binary.little_endian_put_u32(mut tag[4..8], h1)
	binary.little_endian_put_u32(mut tag[8..12], h2)
	binary.little_endian_put_u32(mut tag[12..16], h3)

	// its tell the mac has been done, and prevent data to be feeded to input call.
	p.done = true
	// zeroize all internal state	
	p.zeroize()

	return tag
}

// process_the_block computes a single block of Poly1305 using the internal buffer
fn (mut p Poly1305) process_the_block(finished bool) {
	hibit := if finished { 0 } else { 1 << 24 }

	r0 := p.r[0]
	r1 := p.r[1]
	r2 := p.r[2]
	r3 := p.r[3]
	r4 := p.r[4]

	s1 := r1 * 5
	s2 := r2 * 5
	s3 := r3 * 5
	s4 := r4 * 5

	mut h0 := p.h[0]
	mut h1 := p.h[1]
	mut h2 := p.h[2]
	mut h3 := p.h[3]
	mut h4 := p.h[4]

	// h += m
	h0 += (binary.little_endian_u32(p.buffer[0..4])) & 0x3ffffff
	h1 += (binary.little_endian_u32(p.buffer[3..7]) >> 2) & 0x3ffffff
	h2 += (binary.little_endian_u32(p.buffer[6..10]) >> 4) & 0x3ffffff
	h3 += (binary.little_endian_u32(p.buffer[9..13]) >> 6) & 0x3ffffff
	h4 += (binary.little_endian_u32(p.buffer[12..16]) >> 8) | u32(hibit) // its cast from int

	// h *= r
	d0 := (u64(h0) * u64(r0)) + (u64(h1) * u64(s4)) + (u64(h2) * u64(s3)) + (u64(h3) * u64(s2)) +
		(u64(h4) * u64(s1))

	mut d1 := (u64(h0) * u64(r1)) + (u64(h1) * u64(r0)) + (u64(h2) * u64(s4)) +
		(u64(h3) * u64(s3)) + (u64(h4) * u64(s2))

	mut d2 := (u64(h0) * u64(r2)) + (u64(h1) * u64(r1)) + (u64(h2) * u64(r0)) +
		(u64(h3) * u64(s4)) + (u64(h4) * u64(s3))

	mut d3 := (u64(h0) * u64(r3)) + (u64(h1) * u64(r2)) + (u64(h2) * u64(r1)) +
		(u64(h3) * u64(r0)) + (u64(h4) * u64(s4))

	mut d4 := (u64(h0) * u64(r4)) + (u64(h1) * u64(r3)) + (u64(h2) * u64(r2)) +
		(u64(h3) * u64(r1)) + (u64(h4) * u64(r0))

	// (partial) h %= p
	mut c := u32(0)
	c = u32(d0 >> 26) // as u32
	h0 = u32(d0) & 0x3ffffff // as u32
	d1 += u64(c)

	c = u32(d1 >> 26) // as u32
	h1 = u32(d1) & 0x3ffffff // d1 as u32 & 0x3ffffff
	d2 += u64(c)

	c = u32(d2 >> 26) // as u32
	h2 = u32(d2) & 0x3ffffff // d2 as u32 & 0x3ffffff
	d3 += u64(c)

	c = u32(d3 >> 26) //(d3 >> 26) as u32
	h3 = u32(d3) & 0x3ffffff // d3 as u32 & 0x3ffffff
	d4 += u64(c)

	c = u32(d4 >> 26) // (d4 >> 26) as u32
	h4 = u32(d4) & 0x3ffffff // d4 as u32 & 0x3ffffff
	h0 += c * 5

	c = h0 >> 26
	h0 &= 0x3ffffff
	h1 += c

	p.h[0] = h0
	p.h[1] = h1
	p.h[2] = h2
	p.h[3] = h3
	p.h[4] = h4
}

fn (mut p Poly1305) zeroize() {
	// zeroize r and h
	for i := 0; i < 5; i++ {
		p.r[i] = 0
	}
	for m := 0; m < 5; m++ {
		p.h[m] = 0
	}
	// zeroize s
	for j := 0; j < 4; j++ {
		p.s[j] = 0
	}

	// zeroize internal buffer
	for k := 0; k < p.buffer.len; k++ {
		p.buffer[k] = u8(0x00)
	}
}
