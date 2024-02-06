module poly1305

import math.bits
import math.unsigned

const uint192_zero = Uint192{}

// Uint192 is a custom allocators that represents 192 bits of unsigned integer.
struct Uint192 {
mut:
	lo u64
	mi u64
	hi u64
}

// We define several required functionality on this custom allocator.
//	
// add_with_carry returns u+v with carry
fn (u Uint192) add_checked(v Uint192, c u64) (Uint192, u64) {
	lo, c0 := bits.add_64(u.lo, v.lo, c)
	mi, c1 := bits.add_64(u.mi, v.mi, c0)
	hi, c2 := bits.add_64(u.hi, v.hi, c1)
	x := Uint192{lo, mi, hi}
	return x, c2
}

// add_with_carry returns u+v with carry
fn (u Uint192) add_128_checked(v unsigned.Uint128, c u64) (Uint192, u64) {
	lo, c0 := bits.add_64(u.lo, v.lo, c)
	mi, c1 := bits.add_64(u.mi, v.hi, c0)
	hi, c2 := bits.add_64(u.hi, 0, c1)
	x := Uint192{lo, mi, hi}
	return x, c2
}

fn (u Uint192) add_64_checked(v u64, c u64) (Uint192, u64) {
	lo, c0 := bits.add_64(u.lo, v, c)
	mi, c1 := bits.add_64(u.mi, 0, c0)
	hi, c2 := bits.add_64(u.hi, 0, c1)
	x := Uint192{lo, mi, hi}
	return x, c2
}

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
	m0 := u128_from_64_mul(u.lo, v)
	m1 := u128_from_64_mul(u.mi, v)
	m2 := u128_from_64_mul(u.hi, v)
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
	//   uhi*vhi    umi*vhi      ulo*vhi
	// ----------------------------------------------
	//		  m3         m2          m1           m0       // Uint128
	//
	// -----------------------------------------------
	//		m3.hi		m2.hi		m1.hi		m0.hi
	//					m3.lo		m2.lo		m1.lo	m0.lo
	// ------------------------------------------------------ +
	// 	   	t4			t3		 	t2			t1		t0
	//
	ulovlo := u128_from_64_mul(u.lo, v.lo)
	umivlo := u128_from_64_mul(u.mi, v.lo)
	uhivlo := u128_from_64_mul(u.hi, v.lo)
	//
	ulovhi := u128_from_64_mul(u.lo, v.hi)
	umivhi := u128_from_64_mul(u.mi, v.hi)
	uhivhi := u128_from_64_mul(u.hi, v.hi)
	//
	m0 := ulovlo
	m1, c1 := unsigned.add_128(umivlo, ulovhi, 0)
	m2, c2 := unsigned.add_128(uhivlo, umivhi, c1)
	m3, c3 := unsigned.add_128(uhivhi, unsigned.uint128_zero, c2)
	if c3 != 0 {
		panic('Uint192: unexpected overflow')
	}
	//
	t0 := m0.lo
	t1, c4 := bits.add_64(m0.hi, m1.lo, 0)
	t2, c5 := bits.add_64(m1.hi, m2.lo, c4)
	t3, c6 := bits.add_64(m2.hi, m3.lo, c5)
	t4, c7 := bits.add_64(m3.hi, 0, c6)
	if c7 != 0 {
		panic('Uint192: unexpected overflow')
	}

	x := Uint192{
		lo: t0
		mi: t1
		hi: t2
	}
	hb := unsigned.uint128_new(t3, t4)
	return x, hb
}

// u128_from_64_mul creates new Uint128 from 64x64 bit product of x*y
fn u128_from_64_mul(x u64, y u64) unsigned.Uint128 {
	hi, lo := bits.mul_64(x, y)
	return unsigned.uint128_new(lo, hi)
}

// select_64 returns x if v == 1 and y if v == 0, in constant time.
fn select_64(v u64, x u64, y u64) u64 {
	return ~(v - 1) & x | (v - 1) & y
}

fn shift_right_by2(mut a unsigned.Uint128) unsigned.Uint128 {
	a.lo = a.lo >> 2 | (a.hi & 3) << 62
	a.hi = a.hi >> 2
	return a
}
