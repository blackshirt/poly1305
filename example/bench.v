module main

import rand
import time
import math.stats
import blackshirt.poly1305

const (
	default_numiter = 100000
	key             = rand.bytes(32) or { panic(err.msg) }
)

fn poly32_create_mac_for_1k_msg_bench() ? {
	msg := rand.bytes(1024)?
	numiter := 1000
	mut durations_times := []i64{}

	for i := 0; i <= numiter; i++ {
		mut sw := time.new_stopwatch()
		_ := poly1305.create_mac(msg, key)?
		duration := sw.elapsed().nanoseconds()
		durations_times << duration
	}

	println('Stats of benchmarking of ${@FN} function')
	println('Number of iterations: ${numiter} x')
	print_bench_results(durations_times)
}

fn print_bench_results(s []i64) {
	println('Average: \t${stats.mean[i64](s)} ns')
	println('Minimal: \t${stats.min[i64](s)} ns')
	println('Maximal: \t${stats.max[i64](s)} ns')
}

fn main() {
	poly32_create_mac_for_1k_msg_bench()?
}
