module poly1305

import rand
import encoding.hex

fn test_poly1305_with_smoked_messages_are_working_normally() ! {
	key := rand.bytes(32)!
	// generates smoked message with full bits is set
	msg := u8(0xff).repeat(135).bytes()
	// msg = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
	mut tag := []u8{len: tag_size}
	create_tag(mut tag, msg, key)!

	// lets verify its working normally
	valid := verify_tag(tag, msg, key)
	assert valid == true
}

// This is a test case from RFC 8439 vector test data.
// There are 12 cases provided.
fn test_poly1305_core_vector_tests() ! {
	for i, c in poly1305.basic_poly_cases {
		mut key := hex.decode(c.key) or { panic(err.msg()) }
		mut msg := hex.decode(c.msg) or { panic(err.msg()) }
		mut msg2 := msg.clone()
		msg3 := msg.clone()
		expected_tag := hex.decode(c.tag) or { panic(err.msg()) }

		mut tag := []u8{len: tag_size}

		// check for instance based method
		mut p2 := new(key)!
		// msg is mut, so we provide the clone
		p2.update_block(mut msg2)
		p2.finish(mut tag)
		// check tag same with expected_tag
		assert tag == expected_tag
		// verify the tag has right result
		assert verify_tag(tag, msg3, key) == true

		mut tag2 := []u8{len: tag_size}
		create_tag(mut tag2, msg3, key)!
		assert tag2 == expected_tag
		assert verify_tag(tag2, msg3, key) == true
	}
}

fn test_poly1305_function_based_core_functionality() ! {
	for i, c in poly1305.basic_poly_cases {
		mut key := hex.decode(c.key) or { panic(err.msg()) }
		mut msg := hex.decode(c.msg) or { panic(err.msg()) }

		expected_tag := hex.decode(c.tag) or { panic(err.msg()) }
		mut tag := []u8{len: tag_size}

		mut po := new(key)!
		update_generic(mut po, mut msg)
		finalize(mut tag, mut po.h, po.s)
		assert tag == expected_tag
	}
}

// its comes from golang poly1305 vector test, except minus with changed internal state test
fn test_smoked_data_vectors() ! {
	for i, c in testdata {
		mut key := hex.decode(c.key)!
		mut msg := hex.decode(c.msg)!
		expected_tag := hex.decode(c.tag)!

		mut poly := new(key)!
		mut tag := []u8{len: tag_size}

		poly.update(msg)
		poly.finish(mut tag)

		assert tag == expected_tag

		mut res := verify_tag(tag, msg, key)
		assert res == true

		// If the key is zero, the tag will always be zero, independent of the input.
		if msg.len > 0 && key.len != 32 {
			msg[0] ^= 0xff
			res = verify_tag(tag, msg, key)
			assert res == false
			msg[0] ^= 0xff
		}

		// If the input is empty, the tag only depends on the second half of the key.
		if msg.len > 0 {
			key[0] ^= 0xff
			res = verify_tag(tag, msg, key)
			assert res == false
			key[0] ^= 0xff
		}
		tag[0] ^= 0xff
		res = verify_tag(tag, msg, key)
		assert res == false
		tag[0] ^= 0xff
	}
}

struct RFCTestCases {
	key string
	msg string
	tag string
}

const basic_poly_cases = [
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
	// reduced!
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
	// Test Vector #6: What happens if addition of s overflows modulo 2^128!
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
	// carry from lower limb!
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
	// exactly 2^130-5!
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
	//  exactly 2^130-6!
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
	//  131-bit intermediate result!
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
	//   131-bit final result!
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
