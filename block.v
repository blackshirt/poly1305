// This is internally same as write or write_padded
// but for conveniences, its available to mimic from rust version
module poly1305

import arrays
import encoding.binary
import crypto.internal.subtle

type Block = []byte

//  Input data into the universal hash function. If the length of the
//  data is not a multiple of the block size, the remaining data is
//  padded with zeroes up to the `BlockSize`.
//
//  This approach is frequently used by AEAD modes which use
//  Message Authentication Codes (MACs) based on universal hashing.
fn update_padded(mut st Poly1305, data []byte) {
	// mut chunks = data.chunks_exact(Self::BlockSize::to_usize());
	mut chunks := arrays.chunk<byte>(data, block_size)

	// check if last item of the chunks is unaligned with block size,
	// if unaligned, pad associated data with `0` byte
	if chunks.last().len % block_size != 0 {
		mut padded_block := []byte{len: block_size}
		subtle.constant_time_copy(1, mut padded_block[..chunks.last().len], chunks.last())
		chunks[chunks.len - 1] = padded_block
	}

	for chunk in chunks {
		compute_block(mut st, chunk, false)
	}
}

// compute_unpadded computes unpadded tag for the given input data.
fn (mut st Poly1305) compute_unpadded(data []byte) []byte {
	// for chunk in data.chunks(block_size) {
	for chunk in arrays.chunk<byte>(data, poly1305.block_size) {
		if chunk.len == poly1305.block_size {
			// block := chunk.clone()
			st.buffer = chunk
			st.process_block(false)
		} else {
			mut block := []byte{len: poly1305.block_size}
			subtle.constant_time_copy(1, mut block[..chunk.len], chunk)
			block[chunk.len] = byte(0x01)
			st.buffer = block
			st.process_block(true)
		}
	}

	return st.finalize()
}

fn compute_block(mut st Poly1305, b Block, partial bool) {
	hibit := if partial { 0 } else { u32(1) << 24 }

	mut msg := b.clone()

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
