package main

import (
	"runtime"
	"testing"
)

func BenchmarkQuerySystemProcessorCycle_System(b *testing.B) {
	n := runtime.NumCPU()
	for i := 0; i < b.N; i++ {
		_, err := QuerySystemProcessorCycle(SystemProcessorCycleTimeInformation, uint32(n))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQuerySystemProcessorCycle_Idle(b *testing.B) {
	n := runtime.NumCPU()
	for i := 0; i < b.N; i++ {
		_, err := QuerySystemProcessorCycle(SystemProcessorIdleCycleTimeInformation, uint32(n))
		if err != nil {
			b.Fatal(err)
		}
	}
}

// UpdateSystemProcessorCycleTime

func BenchmarkUpdateSystemProcessorCycleTime(b *testing.B) {
	var idl Uint64Delta
	var sys Uint64Delta
	for i := 0; i < b.N; i++ {
		if err := UpdateSystemProcessorCycleTime(&idl, &sys); err != nil {
			b.Fatal(err)
		}
	}
}
