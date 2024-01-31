module poly1305


fn poly1305_block(ctx Poly1305, mut m []u8) {
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
	
	mut length := m.len 
	for length >= block_size {
		// h += m 
		m0 := 
	}
	
	ctx.h[0] = h0
	ctx.h[1] = h1
	ctx.h[2] = h2
}