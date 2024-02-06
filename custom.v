module poly1305

import math.bits

// Uint192 is a custom allocators that represents 192 bits of unsigned integer.
// Maybe this structure could supplement `math.unsigned` module, but it is another story.
struct Uint192 {
	lo u64
	mi u64
	hi u64
}
	
// add_with_carry returns u+v with carry
fn (u Uint192) add_with_carry(v Uint192, c u64) (Uint192, u64) {
	lo, c0 := bits.add_64(u.lo, v.lo, c)
	mi, c1 := bits.add_64(u.mi, v.mi, c0)
	hi, c2 := bits.add_64(u.hi, v.hi, c1)
	x := Uint192{lo, mi, hi}
	return x, c2
}
	
fn (u Uint192) add_64(v u64) (Uint192, u64) {
	lo, c0 := bits.add_64(u.lo, v, 0)
	mi, c1 := bits.add_64(u.mi, 0, c0)
	hi, c2 := bits.add_64(u.hi, 0, c1)
	x := Uint192{lo, mi, hi}
	return x, c2
}
	
// We define several required functionality on this custom allocator.
//
// mul_64_checked returns u*v even the result size is over > 192 bit.
// It return (Uin192, u64) pair where the former stores low 192 bit and 
// and the rest of high bit stored in the u64 part. You can check the value of u64 part
// for v != 0, its mean, the product of u*v is overflowing 192 bits.
fn (u Uint192) mul_64_checked(v u64) (Uint192, u64) {
	//         u.hi	  u.mi   u.lo
	//							v
	// --------------------------------- x
	// 	        m2	    m1	   m0 				// 128 bit product
	// -----------------------------------
	// 	     m2.hi    m1.hi   m0.hi			
	//		          m2.lo   m1.lo    m0.lo
	// ------------------------------------------- +
	//	       t3	     t2		 t1		 t0	 
	// 
	m0 := u128_mul(u.lo, v)
	m1 := u128_mul(u.mi, v)
	m2 := u128_mul(u.hi, v)
	// propagates carry
	t0, c0 := bits.add_64(m0.lo, 0, 0)
	t1, c1 := bits.add_64(m0.hi, m1.lo, c0)
	t2, c2 := bits.add_64(m1.hi, m2.lo, c1)
	t3, c3 := bits.add_64(m2.hi, 0, c2)
	// something bad happen if the last c3 is non null
	if c3 != 0 {
		panic('Uint192: unexpected overflow')
	}
	x := Uint192{
		lo: t0
		mi: t1
		hi: t2
	}
	return x, t3
}
		
// mul_128_checked returns u*v even the result is over > 192 bits.
// Its stores the remaining high bits of the reault in Uint128 structure.
fn (u Uint192) mul_128_checked(v unsigned.Uint128) (Uint192, unsigned.Uint128) {
	// 		        u.hi	    u.mi         u.lo
	//				            v.hi         v.lo     
	// --------------------------------------------x
	//              uhi*vlo      umi*vlo     ulo*vlo
	//   uhi*vhu    umi*vhi      ulo*vhi
	// ----------------------------------------------
	//		  m3         m2          m1           m0       // Uint128
	// 
	// -----------------------------------------------
	//		m3.hi		m2.hi		m1.hi		m0.hi
	//					m3.lo		m2.lo		m1.lo	m0.lo
	// ------------------------------------------------------ +
	// 	   	t4			t3		 	t2			t1		t0
	//
	
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
