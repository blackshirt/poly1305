module poly1305


fn poly1305_blocks(mut po Poly1305, msg []u8) {
    if msg.len == 0 { return } 
	if po.r.lo & poly1305.not_rmask0 != 0 && po.r.hi & poly1305.not_rmask1 != 0 {
		panic('poly1305: bad unclamped of r')
	}
	
	if po.h.hi & poly1305.mask_high60bits != 0 {
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
        if msglen >= poly1305.block_size {
            // take msg block 
            block := msg[idx .. idx+block_size]
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
            mut buf := []u8{len: poly1305.block_size}
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

fn poly1305_update(mut po Poly1305, mut msg []u8) {
	if po.leftover > 0 {
		want := math.min(poly1305.block_size - po.leftover, msg.len)
		dump(want)
		dump(msg.len)
		//mm := msg[..want].clone()
		_ := copy(mut po.buffer[po.leftover..], msg[..want])
		// for i, v in mm {
		//		po.buffer[po.leftover + i] = v
		//}

		msg = unsafe { msg[want..] }
		po.leftover += want

		if po.leftover < poly1305.block_size {
			return
		}
		update_generic(mut po, mut po.buffer)
		// po.process_the_block(false)
		po.leftover = 0
	}

	for msg.len >= poly1305.block_size {
		// subtle.constant_time_copy(1, mut po.buffer, msg[..poly1305.block_size])
		_ := copy(mut po.buffer, msg[..poly1305.block_size])
		// po.process_the_block(false)
		update_generic(mut po, mut po.buffer)
		msg = unsafe { msg[poly1305.block_size..] }
	}
	if msg.len > 0 {
		subtle.constant_time_copy(1, mut po.buffer[..msg.len], msg)
		// po.leftover = msg.len
		// po.leftover += copy(mut po.buffer[po.leftover..], msg)
	}
}
