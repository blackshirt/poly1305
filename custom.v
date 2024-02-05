module poly1305

import math.bits

// custom allocators that align with existing builtin structures
// Internally it currently uses the Uint256 structure as a custom allocator
type Acc = unsigned.Uint256

// mul_64 returns u*v even the result size is over > 256 bit
// its acts like Uint128.overflowing_mul_64 but return value instead of boolean.
fn (u Acc) mul_64_checked(v u64) (Acc, u64) {
	//           u.hi	      u.lo
	//							v
	// --------------------------------- x
	// 				m1			m0 					// 128 bit product
	// -----------------------------------
	// 	 m3.hi	  m2.hi			
	//			  m3.lo				m0.lo
	// ------------------------------------------- +
	//	  t4	  t3		 t2		 t1		  t0
	m0 := u128_mul(u.lo.lo, v)
	m1 := u128_mul(u.lo.hi, v)
	m2 := u128_mul(u.hi.lo, v)
	m3 := u128_mul(u.hi.hi, v)
	//
	t0, c0 := bits.add_64(m0.lo, 0, 0)
	t1, c1 := bits.add_64(m0.hi, m1.lo, c0)
	t2, c2 := bits.add_64(m1.hi, m2.lo, c1)
	t3, c3 := bits.add_64(m2.hi, m3.lo, c2)
	t4, c4 := bits.add_64(m3.hi, 0, c3)
	if c4 != 0 {
		panic('Custom Acc overflow')
	}
	x := unsigned.Uint256
	{
		lo:
		unsigned.uint128_new(t0, t1)
		hi:
		unsigned.uint128_new(t2, t3)
	}
	return Acc(x), t4
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
