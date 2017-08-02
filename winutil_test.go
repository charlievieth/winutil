package main

import (
	"runtime"
	"testing"
)

func BenchmarkQuerySystemProcessorCycle(b *testing.B) {
	n := runtime.NumCPU()
	for i := 0; i < b.N; i++ {
		_, err := QuerySystemProcessorCycle(SystemProcessorCycleTimeInformation, uint32(n))
		if err != nil {
			b.Fatal(err)
		}
	}
}
