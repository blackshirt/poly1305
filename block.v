module poly1305

import math
import math.bits
import math.unsigned
import encoding.binary
import crypto.internal.subtle

fn poly1305_blocks(mut po Poly1305, msg []u8) {
	if msg.len == 0 {
		return
	}
	if po.r.lo & not_rmask0 != 0 && po.r.hi & not_rmask1 != 0 {
		panic('poly1305: bad unclamped of r')
	}

	if po.h.hi & mask_high60bits != 0 {
		panic('poly1305: h need to be reduced')
	}

	// localize the thing
	mut h := po.h
	mut t := [4]u64{}
	mut msglen := msg.len
	mut idx := 0

	for msglen > 0 {
		// carry
		mut c := u64(0)
		if msglen >= block_size {
			// take msg block
			block := msg[idx..idx + block_size]

			// h += m
			m := unsigned.Uint128{
				lo: binary.little_endian_u64(block[0..8])
				hi: binary.little_endian_u64(block[8..16])
			}
			h, c = h.add_128_checked(m, 0)

			// h.hi has been checked above, so, its safe to assume its not overflow
			h.hi += c + 1 // c = bits.add_64(h.hi, 1, c)
			idx += block_size
			msglen -= block_size
		} else {
			mut buf := []u8{len: block_size}
			subtle.constant_time_copy(1, mut buf[..msglen], msg)

			// set a bit above msg size.
			buf[msglen] = u8(0x01)
			m := unsigned.Uint128{
				lo: binary.little_endian_u64(buf[0..8])
				hi: binary.little_endian_u64(buf[8..16])
			}

			// add this number to the accumulator, ie, h += m
			h, c = h.add_128_checked(m, 0)
			h.hi, c = bits.add_64(h.hi, 0, c)
			if c != 0 {
				panic('poly1305: something bad')
			}
			msglen = 0
		}

		//
		// perform h *= r and then reduce output by modulo p
		mul_h_by_r(mut t, mut h, po.r)

		squeeze(mut h, t)
	}

	// updates internal accumulator
	po.h = h
}

fn poly1305_update(mut po Poly1305, msg []u8) {
	if msg.len == 0 {
		return
	}
	mut msglen := msg.len
	mut idx := 0
	if po.leftover > 0 {
		want := math.min(block_size - po.leftover, msglen)
		// mm := msg[..want].clone()
		block := msg[idx..idx + want]
		_ := copy(mut po.buffer[po.leftover..], block)

		msglen -= want
		idx += want
		po.leftover += want

		if po.leftover < block_size {
			return
		}
		// update_generic(mut po, mut po.buffer)
		poly1305_blocks(mut po, po.buffer)

		po.leftover = 0
	}

	if msglen >= block_size {
		want := (msglen & ~(block_size - 1))
		block := msg[idx..idx + want]
		poly1305_blocks(mut po, block)
		idx += want
		msglen -= want
	}
	if msglen > 0 {
		// subtle.constant_time_copy(1, mut po.buffer[..msg.len], msg)

		// po.leftover = msg.len
		po.leftover += copy(mut po.buffer[po.leftover..], msg[idx..])
	}
}
