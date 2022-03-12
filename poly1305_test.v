module poly1305

import arrays
import encoding.hex

// This is a test case from RFC 8439 vector test data.
// There are 12 cases provided.
fn test_poly1305_core_vector_tests() ? {
	for i, c in poly1305.basic_poly_cases {
		mut key := hex.decode(c.key) or { panic(err.msg) }
		mut msg := hex.decode(c.msg) or { panic(err.msg) }
		expected_tag := hex.decode(c.tag) or { panic(err.msg) }

		mut poly := new_with_key(key) or { panic(err.msg) }
		// poly1305_init(mut poly, key)
		poly.write(msg)
		tag := poly.finalize()
		assert tag == expected_tag
		mut res := verify_mac(tag, msg, key) or { panic(err.msg) }
		assert res == true

		mac := create_mac(msg, key) or { panic(err.msg) }
		assert mac == expected_tag
		res = verify_mac(mac, msg, key) or { panic(err.msg) }
		assert res == true

		mut p := new_with_key(key) or { panic(err.msg) }
		p.write(msg)

		assert p.verify(expected_tag) == true
	}
}

fn test_nacl_vector() {
	key := hex.decode('eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880') or {
		panic(err.msg)
	}

	msg := hex.decode('8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5') or {
		panic(err.msg)
	}

	expected := hex.decode('f3ffc7703f9400e52a7dfb4b3d3305d9') or { panic(err.msg) }
	mut p := new_with_key(key) or { panic(err.msg) }
	result1 := p.compute_unpadded(msg)

	assert expected == result1
}

fn test_donna_self_test1() {
	// This gives r = 2 and s = 0.
	key := hex.decode('0200000000000000000000000000000000000000000000000000000000000000') or {
		panic(err.msg)
	}

	// This results in a 130-bit integer with the lower 129 bits all set: m = (1 << 129) - 1
	msg := hex.decode('ffffffffffffffffffffffffffffffff') or { panic(err.msg) }

	// The input is a single block, so we should have the following computation:
	//     tag = ((m * r) % p) + s
	//         = ((((1 << 129) - 1) * 2) % p) + 0
	//         = ((1 << 130) - 2) % (1 << 130) - 5
	//         = 3
	expected := hex.decode('03000000000000000000000000000000') or { panic(err.msg) }

	mut poly := new_with_key(key) or { panic(err.msg) }
	poly.write(msg)
	assert expected == poly.finalize()
}

fn test_write_padded_input() {
	// poly1305 key and AAD from <https://tools.ietf.org/html/rfc8439#section-2.8.2>
	key := hex.decode('7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff') or {
		panic(err.msg)
	}
	msg := hex.decode('50515253c0c1c2c3c4c5c6c7') or { panic(err.msg) }
	expected := hex.decode('ada56caa480fe6f5067039244a3d76ba') or { panic(err.msg) }

	mut poly := new_with_key(key) or { panic(err.msg) }
	poly.write_padded(msg)
	assert expected == poly.finalize()
}

fn test_update_padded_input() {
	// poly1305 key and AAD from <https://tools.ietf.org/html/rfc8439#section-2.8.2>
	key := hex.decode('7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff') or {
		panic(err.msg)
	}
	msg := hex.decode('50515253c0c1c2c3c4c5c6c7') or { panic(err.msg) }
	expected := hex.decode('ada56caa480fe6f5067039244a3d76ba') or { panic(err.msg) }

	mut poly := new_with_key(key) or { panic(err.msg) }
	update_padded(mut poly, msg)
	assert expected == poly.finalize()
}

fn test_tls_vectors() {
	// from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
	key := 'this is 32-byte key for Poly1305'.bytes()
	msg := []byte{len: 32}
	expected := hex.decode('49ec78090e481ec6c26b33b91ccc0307') or { panic(err.msg) }

	mut poly := new_with_key(key) or { panic(err.msg) }

	for chunk in arrays.chunk<byte>(msg, block_size) {
		poly.write(chunk)
	}
	assert expected == poly.finalize()
}

fn test_rfc7539_vector() {
	// From <https://tools.ietf.org/html/rfc7539#section-2.5.2>
	key := hex.decode('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b') or {
		panic(err.msg)
	}
	msg := hex.decode('43727970746f6772617068696320466f72756d2052657365617263682047726f7570') or {
		panic(err.msg)
	}
	expected := hex.decode('a8061dc1305136c6c22b8baf0c0127a9') or { panic(err.msg) }

	mut poly := new_with_key(key) or { panic(err.msg) }
	// result := poly.compute_unpadded(msg)
	poly.write(msg)
	result := poly.finalize()
	assert result == expected
}

fn test_donna_self_test2() {
	total_key := hex.decode('01020304050607fffefdfcfbfaf9ffffffffffffffffffffffffffff00000000') or {
		panic(err.msg)
	}
	total_mac := hex.decode('64afe2e8d6ad7bbdd287f97c44623d39') or { panic(err.msg) }

	mut tpoly := new_with_key(total_key) or { panic(err.msg) }

	for i in 0 .. 256 {
		mut key := []byte{len: key_size}
		b := byte(i)
		s := b.repeat(key_size) // string
		copy(mut key, s.bytes())

		msg := b.repeat(256).bytes()
		mut p := new_with_key(key) or { panic(err.msg) }
		tag := p.compute_unpadded(msg[..i])
		tpoly.write(tag)
	}
	//
	assert total_mac == tpoly.finalize()
}

struct RFCTestCases {
	key string
	msg string
	tag string
}

const (
	basic_poly_cases = [
		// 0. core basic example test
		RFCTestCases{
			key: '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b'
			msg: '43727970746f6772617068696320466f72756d2052657365617263682047726f7570'
			tag: 'a8061dc1305136c6c22b8baf0c0127a9'
		},
		// https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.3
		// 1. A.3.1 case
		RFCTestCases{
			key: '0000000000000000000000000000000000000000000000000000000000000000'
			msg: '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
			tag: '00000000000000000000000000000000'
		},
		// 2. A.3.2 case
		RFCTestCases{
			key: '0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e'
			msg: '416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f'
			tag: '36e5f6b5c5e06070f0efca96227a863e'
		},
		// 3. A.3.3 case
		RFCTestCases{
			key: '36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000'
			msg: '416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f'
			tag: 'f3477e7cd95417af89a6b8794c310cf0'
		},
		// 4. A.3.4 case
		RFCTestCases{
			key: '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0'
			msg: '2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e'
			tag: '4541669a7eaaee61e708dc7cbcc5eb62'
		},
		// Test Vector #5: If one uses 130-bit partial reduction, does the code
		// handle the case where partially reduced final result is not fully
		// reduced?
		// r := '02000000000000000000000000000000'
		// s := '00000000000000000000000000000000'
		// data := 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
		// result_tag := '03000000000000000000000000000000'
		// key := r + s
		RFCTestCases{
			key: '0200000000000000000000000000000000000000000000000000000000000000'
			msg: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
			tag: '03000000000000000000000000000000'
		},
		// Test Vector #6: What happens if addition of s overflows modulo 2^128?
		// r := '02000000000000000000000000000000'
		// s := 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
		// data := '02000000000000000000000000000000'
		// result_tag := '03000000000000000000000000000000'
		// key := r + s
		RFCTestCases{
			key: '02000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
			msg: '02000000000000000000000000000000'
			tag: '03000000000000000000000000000000'
		},
		// Test Vector #7: What happens if data limb is all ones and there is
		// carry from lower limb?
		// r := '01000000000000000000000000000000'
		// s := '00000000000000000000000000000000'
		// data := 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF11000000000000000000000000000000'
		// result_tag := '05000000000000000000000000000000'
		RFCTestCases{
			key: '0100000000000000000000000000000000000000000000000000000000000000'
			msg: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF11000000000000000000000000000000'
			tag: '05000000000000000000000000000000'
		},
		// Test Vector #8: What happens if final result from polynomial part is
		// exactly 2^130-5?
		// r := '01000000000000000000000000000000'
		// s := '00000000000000000000000000000000'
		// data := 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE01010101010101010101010101010101'
		// result_tag := '00000000000000000000000000000000'
		RFCTestCases{
			key: '0100000000000000000000000000000000000000000000000000000000000000'
			msg: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE01010101010101010101010101010101'
			tag: '00000000000000000000000000000000'
		},
		// Test Vector #9: What happens if final result from polynomial part is
		//  exactly 2^130-6?
		// r := '02000000000000000000000000000000'
		// s := '00000000000000000000000000000000'
		// data := 'FDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
		// result_tag := 'FAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
		RFCTestCases{
			key: '0200000000000000000000000000000000000000000000000000000000000000'
			msg: 'FDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
			tag: 'FAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
		},
		// Test Vector #10: What happens if 5*H+L-type reduction produces
		//  131-bit intermediate result?
		// r := '01000000000000000400000000000000'
		// s := '00000000000000000000000000000000'
		// data := 'E33594D7505E43B900000000000000003394D7505E4379CD01000000000000000000000000000000000000000000000001000000000000000000000000000000'
		// result_tag := '14000000000000005500000000000000'
		RFCTestCases{
			key: '0100000000000000040000000000000000000000000000000000000000000000'
			msg: 'E33594D7505E43B900000000000000003394D7505E4379CD01000000000000000000000000000000000000000000000001000000000000000000000000000000'
			tag: '14000000000000005500000000000000'
		},
		// Test Vector #11: What happens if 5*H+L-type reduction produces
		//   131-bit final result?
		// r := '01000000000000000400000000000000'
		// s := '00000000000000000000000000000000'
		// data := 'E33594D7505E43B900000000000000003394D7505E4379CD010000000000000000000000000000000000000000000000'
		// result_tag := '13000000000000000000000000000000'
		RFCTestCases{
			key: '0100000000000000040000000000000000000000000000000000000000000000'
			msg: 'E33594D7505E43B900000000000000003394D7505E4379CD010000000000000000000000000000000000000000000000'
			tag: '13000000000000000000000000000000'
		},
	]
)
