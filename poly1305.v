// Copyright (c) 2022 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Poly1305 is a one-time authenticator designed by D. J. Bernstein.
// Poly1305 takes a 32-byte one-time key and a message and produces a
// 16-byte tag.  This tag is used to authenticate the message.
module poly1305

import math
import encoding.binary
import crypto.internal.subtle

const (
	err_key_size = error('Error key size provided')
)

pub const (
	// key_size is size of key for Poly1305, in bytes
	key_size   = 32

	// block_size is size of chunk of bytes to process in
	block_size = 16

	// tag_size is size of output Poly1305 one-time mac in bytes
	tag_size   = 16
)

struct Poly1305 {
mut:
	// the key is partitioned into two secret parts, called "r" and "s"
	r [5]u32
	s [4]u32
	// accumulator of Poly1305 process block
	h [5]u32
	// tell many bytes to process
	leftover int
	// internal buffer with size of block_size
	buffer []byte
	// internal flag to tell Poly1305 have been done.
	done bool
}

// create_mac generates poly1305's tag authenticator for given msg using a one-time key and
// return the 16-byte result. The key must be unique for each message, authenticating two
// different messages with the same key allows an attacker to forge messages at will.
pub fn create_mac(msg []byte, key []byte) ?[]byte {
	mut p := new_with_key(key) ?
	p.write(msg)
	return p.finalize()
}

// verify verifies mac is a valid authenticator for msg with the given key.
// its return true when mac is valid, and false otherwise.
pub fn verify_mac(mac []byte, msg []byte, key []byte) ?bool {
	mut p := new_with_key(key) ?
	p.write(msg)
	tag := p.finalize()
	return subtle.constant_time_compare(mac, tag) == 1
}

// new_with_key creates new Poly1305 MAC instances and initializes its internal state
// with the given key.
// Poly1305 MAC can not be used like common hash, because using a poly1305 key twice breaks its security.
// Therefore feeding data to write to a running MAC after calling finalize causes it to panic.
pub fn new_with_key(key []byte) ?&Poly1305 {
	if key.len != poly1305.key_size {
		return poly1305.err_key_size
	}
	mut st := &Poly1305{
		buffer: []byte{len: poly1305.block_size}
	}

	// load key to the 'r' and 's'
	// and clamping the 'r' part with r &= 0xffffffc0ffffffc0ffffffc0fffffff
	// (r treated as et little-endian number), with clamping, its mean to provide
	// r[3], r[7], r[11], and r[15] are required to have their top four bits clear (be smaller than 16)
	// r[4], r[8], and r[12] are required to have their bottom two bits clear (be divisible by 4)

	st.r[0] = (binary.little_endian_u32(key[0..4])) & 0x3ffffff
	st.r[1] = (binary.little_endian_u32(key[3..7]) >> 2) & 0x3ffff03
	st.r[2] = (binary.little_endian_u32(key[6..10]) >> 4) & 0x3ffc0ff
	st.r[3] = (binary.little_endian_u32(key[9..13]) >> 6) & 0x3f03fff
	st.r[4] = (binary.little_endian_u32(key[12..16]) >> 8) & 0x00fffff

	// this is not need in v, its zeroed by default
	// h = 0
	// st.h[0] = 0
	// st.h[1] = 0
	// st.h[2] = 0
	// st.h[3] = 0
	// st.h[4] = 0

	// save s for later
	st.s[0] = binary.little_endian_u32(key[16..20])
	st.s[1] = binary.little_endian_u32(key[20..24])
	st.s[2] = binary.little_endian_u32(key[24..28])
	st.s[3] = binary.little_endian_u32(key[28..32])

	// initializes this is not needed in V, its zeroed by default
	// st.leftover = 0
	// st.done = false

	return st
}

// verify returns whether the authenticator of all data written to
// the message authentication code matches the expected value.
pub fn (mut st Poly1305) verify(expected []byte) bool {
	if expected.len != poly1305.tag_size {
		return false
	}
	// finalize and produces 16 byte tag after all data written to poly1305 mac internal state
	mac := st.finalize()
	return subtle.constant_time_compare(mac, expected) == 1
}

// chained_write process messages in a chained manner
pub fn (mut p Poly1305) chained_write(msg []byte) Poly1305 {
	p.write(msg)
	return p
}

fn (mut p Poly1305) write_padded(data []byte) {
	p.write(data)

	// Pad associated data with `\0` if it's unaligned with the block size
	unaligned_len := data.len % poly1305.block_size

	if unaligned_len != 0 {
		pad := []byte{len: poly1305.block_size}
		pad_len := poly1305.block_size - unaligned_len
		p.write(pad[..pad_len])
	}
}

// write process msg into the Poly1305 internal state, its panic when
// called after calling finalize.
pub fn (mut st Poly1305) write(msg []byte) {
	if st.done {
		panic(error('poly1305: process message after finalize'))
	}
	mut m := msg.clone()

	if st.leftover > 0 {
		want := math.min(16 - st.leftover, m.len)
		mm := m[..want]
		// for (i, byte) in m.iter().cloned().enumerate().take(want) {
		for i, v in mm {
			st.buffer[st.leftover + i] = v
		}

		m = m[want..]
		st.leftover += want

		if st.leftover < poly1305.block_size {
			return
		}

		st.process_block(false)
		st.leftover = 0
	}

	for m.len >= poly1305.block_size {
		// TODO(tarcieri): avoid a copy here but do for now
		// because it simplifies constant-time assessment.
		subtle.constant_time_copy(1, mut st.buffer, m[..poly1305.block_size])
		st.process_block(false)
		m = m[poly1305.block_size..]
	}

	// st.buffer[..m.len].copy_from_slice(m);
	subtle.constant_time_copy(1, mut st.buffer[..m.len], m)
	st.leftover = m.len
}

// finalize does a final step of reduction, and store accumulator the the 16 byte length mac
pub fn (mut st Poly1305) finalize() []byte {
	// maybe there are the last one block that might be shorter than block_size
	if st.leftover > 0 {
		// Add one bit beyond the number of octets
		st.buffer[st.leftover] = byte(0x01)
		// If the block is not 17 bytes long (the last block), pad it with zeros.
		for i in (st.leftover + 1) .. poly1305.block_size {
			st.buffer[i] = byte(0x00)
		}

		st.process_block(true)
	}

	mut mac := []byte{len: poly1305.block_size}
	mut g0, mut g1, mut g2, mut g3, mut g4 := u32(0), u32(0), u32(0), u32(0), u32(0)
	mut f := u64(0)
	mut c := u32(0)
	mut mask := u32(0)
	// fully carry h
	mut h0 := st.h[0]
	mut h1 := st.h[1]
	mut h2 := st.h[2]
	mut h3 := st.h[3]
	mut h4 := st.h[4]

	c = h1 >> 26
	h1 = h1 & 0x3ffffff
	h2 += c

	c = h2 >> 26
	h2 = h2 & 0x3ffffff
	h3 += c

	c = h3 >> 26
	h3 = h3 & 0x3ffffff
	h4 += c

	c = h4 >> 26
	h4 = h4 & 0x3ffffff

	h0 += c * 5
	c = h0 >> 26
	h0 = h0 & 0x3ffffff
	h1 += c

	// compute h + -p
	g0 = h0 + 5
	c = g0 >> 26
	g0 &= 0x3ffffff

	g1 = h1 + c
	c = g1 >> 26
	g1 &= 0x3ffffff

	g2 = h2 + c
	c = g2 >> 26
	g2 &= 0x3ffffff

	g3 = h3 + c
	c = g3 >> 26
	g3 &= 0x3ffffff
	g4 = h4 + c
	g4 -= (1 << 26)

	// select h if h < p, or h + -p if h >= p
	mask = (g4 >> ((sizeof(u32) * 8) - 1)) - 1
	g0 &= mask
	g1 &= mask
	g2 &= mask
	g3 &= mask
	g4 &= mask
	mask = ~mask
	h0 = (h0 & mask) | g0
	h1 = (h1 & mask) | g1
	h2 = (h2 & mask) | g2
	h3 = (h3 & mask) | g3
	h4 = (h4 & mask) | g4

	// h = h % (2^128)
	h0 = (h0 | (h1 << 26)) & 0xffffffff
	h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff
	h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff

	// Finally, the value of the secret key "s" is added to the accumulator,
	// and the 128 least significant bits are serialized in little-endian
	// order to form the tag.
	// mac = (h + s) % (2^128)
	f = u64(h0) + u64(st.s[0])
	h0 = u32(f)
	f = u64(h1) + u64(st.s[1]) + (f >> 32)
	h1 = u32(f)
	f = u64(h2) + u64(st.s[2]) + (f >> 32)
	h2 = u32(f)
	f = u64(h3) + u64(st.s[3]) + (f >> 32)
	h3 = u32(f)

	// write internal accumulator to the 16 byte length mac
	binary.little_endian_put_u32(mut mac[0..4], h0)
	binary.little_endian_put_u32(mut mac[4..8], h1)
	binary.little_endian_put_u32(mut mac[8..12], h2)
	binary.little_endian_put_u32(mut mac[12..16], h3)

	// tell its has been done
	st.done = true
	// zero out the state
	zeroize(mut st)
	return mac
}

// process_block process block of data  and updates Poly1305 internal's state
fn (mut st Poly1305) process_block(flag_done bool) {
	hibit := if flag_done { 0 } else { u32(1) << 24 }

	mut msg := st.buffer.clone()

	mut d0, mut d1, mut d2, mut d3, mut d4 := u64(0), u64(0), u64(0), u64(0), u64(0)
	mut c := u32(0)

	r0 := st.r[0]
	r1 := st.r[1]
	r2 := st.r[2]
	r3 := st.r[3]
	r4 := st.r[4]

	s1 := r1 * 5
	s2 := r2 * 5
	s3 := r3 * 5
	s4 := r4 * 5

	mut h0 := st.h[0]
	mut h1 := st.h[1]
	mut h2 := st.h[2]
	mut h3 := st.h[3]
	mut h4 := st.h[4]

	// Read the block as a little-endian number
	// Add this number to the accumulator.
	// h += m[i]
	h0 += (binary.little_endian_u32(msg[0..4])) & 0x3ffffff
	h1 += (binary.little_endian_u32(msg[3..7]) >> 2) & 0x3ffffff
	h2 += (binary.little_endian_u32(msg[6..10]) >> 4) & 0x3ffffff
	h3 += (binary.little_endian_u32(msg[9..13]) >> 6) & 0x3ffffff
	h4 += (binary.little_endian_u32(msg[12..16]) >> 8) | hibit

	// Multiply accumulator by "r".
	// h *= r
	d0 = u64(h0) * u64(r0) + u64(h1) * u64(s4) + u64(h2) * u64(s3) + u64(h3) * u64(s2) +
		u64(h4) * u64(s1)
	d1 = u64(h0) * u64(r1) + u64(h1) * u64(r0) + u64(h2) * u64(s4) + u64(h3) * u64(s3) +
		u64(h4) * u64(s2)
	d2 = u64(h0) * u64(r2) + u64(h1) * u64(r1) + u64(h2) * u64(r0) + u64(h3) * u64(s4) +
		u64(h4) * u64(s3)
	d3 = u64(h0) * u64(r3) + u64(h1) * u64(r2) + u64(h2) * u64(r1) + u64(h3) * u64(r0) +
		u64(h4) * u64(s4)
	d4 = u64(h0) * u64(r4) + u64(h1) * u64(r3) + u64(h2) * u64(r2) + u64(h3) * u64(r1) +
		u64(h4) * u64(r0)

	//(partial reduction mod p) h %= p
	c = u32(d0 >> 26)
	h0 = u32(d0) & 0x3ffffff
	d1 += u64(c)

	c = u32(d1 >> 26)
	h1 = u32(d1) & 0x3ffffff
	d2 += u64(c)

	c = u32(d2 >> 26)
	h2 = u32(d2) & 0x3ffffff
	d3 += u64(c)

	c = u32(d3 >> 26)
	h3 = u32(d3) & 0x3ffffff
	d4 += u64(c)

	c = u32(d4 >> 26)
	h4 = u32(d4) & 0x3ffffff

	h0 += c * 5
	c = (h0 >> 26)
	h0 = h0 & 0x3ffffff
	h1 += c

	// update the accumulator
	st.h[0] = h0
	st.h[1] = h1
	st.h[2] = h2
	st.h[3] = h3
	st.h[4] = h4
}

fn zeroize(mut st Poly1305) {
	st.h[0] = 0
	st.h[1] = 0
	st.h[2] = 0
	st.h[3] = 0
	st.h[4] = 0

	st.r[0] = 0
	st.r[1] = 0
	st.r[2] = 0
	st.r[3] = 0
	st.r[4] = 0

	st.s[0] = 0
	st.s[1] = 0
	st.s[2] = 0
	st.s[3] = 0
}
