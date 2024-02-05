module poly1305

import math.bits

// Uint192 is a custom allocators that represents 192 bits of unsigned integer.
// Maybe this structure could supplement `math.unsigned` module, but it is another story.
struct Uint192 {
	lo u64
	mi u64
	hi u64
}
	
// We define several required functionality on this custom allocator.
//
// mul_64_checked returns u*v even the result size is over > 256 bit
// its acts like Uint128.overflowing_mul_64 but return value instead of boolean.
fn (u Uint192) mul_64_checked(v u64) (Uint192, u64) {
	//         u.hi	  u.mi   u.lo
	//							v
	// --------------------------------- x
	// 	  m2		  m1		  m0 				// 128 bit product
	// -----------------------------------
	// 	  m2.hi       m1.hi       m0.hi			
	//		          m2.lo       m1.lo    m0.lo
	// ------------------------------------------- +
	//	    t3	         t2		    t1		 t0	 
	// 
	m0 := u128_mul(u.lo, v)
	m1 := u128_mul(u.mi, v)
	m2 := u128_mul(u.hi, v)
	//
	t0, c0 := bits.add_64(m0.lo, 0, 0)
	t1, c1 := bits.add_64(m0.hi, m1.lo, c0)
	t2, c2 := bits.add_64(m1.hi, m2.lo, c1)
	t3, c3 := bits.add_64(m2.hi, 0, c2)
	if c3 != 0 {
		panic('Custom Acc overflow')
	}
	x := unsigned.Uint192{
		lo: t0
		mi: t1
		hi: t2
	}
	return x, t4
}

fn (u Acc) mul_128_checked(v unsigned.Uint128) (Acc, unsigned.Uint128) {
	// 		u.hi	u.lo
	//				  v
	// ------------------x
	//		 m1		 m0
	// -------------------
	//	m1.hi		m0.hi
	//				m1.lo	m0.lo
	// -------------------------- +
	// 	   t2		t1		 t0
	//
	lov1, lov0 := unsigned.mul_128(u.lo, v)
	hiv1, hiv0 := unsigned.mul_128(u.hi, v)
	//
	m0 := unsigned.Uint256{
		lo: lov0
		hi: lov1
	}
	m1 := unsigned.Uint256{hiv0, hiv1}
	t0 := m0.lo
	t1, c1 := unsigned.add_128(m0.hi, m1.lo, u64(0))
	t2, c2 := unsigned.add_128(m1.hi, 0, c1)
	if c2 != 0 {
		panic('Custom Acc unexpected overflow')
	}

	x := unsigned.Uint256
	{
		t0, t1
	}
	return Acc(x), t2
}
