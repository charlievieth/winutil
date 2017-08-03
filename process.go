// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"unicode/utf16"
	"unsafe"
)

type Tree struct {
	Pid      int
	Parent   *Tree
	Children []*Tree
}

type KPRIORITY int32

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

func (u UNICODE_STRING) String() string {
	if u.Length <= 0 || u.MaximumLength <= 0 || u.Buffer == nil {
		return ""
	}
	// This really shouldn't be possible
	if u.Length&1 == 1 {
		panic(fmt.Sprintf("UNICODE_STRING: odd length: %d", u.Length))
	}
	if u.MaximumLength < u.Length {
		panic(fmt.Sprintf("UNICODE_STRING: Length (%d) exceeds MaximumLength (%d)",
			u.Length, u.MaximumLength))
	}
	// reflect.SliceHeader
	type sliceHeader struct {
		Data uintptr
		Len  int
		Cap  int
	}
	x := *(*[]uint16)(unsafe.Pointer(&sliceHeader{
		Data: uintptr(unsafe.Pointer(u.Buffer)),
		Len:  int(u.Length) / 2,
		Cap:  int(u.MaximumLength) / 2,
	}))
	return string(utf16.Decode(x))
}

func (u UNICODE_STRING) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

type SystemTime struct {
	curr uint64
	prev uint64
	load float64
}

func (s SystemTime) MarshalJSON() ([]byte, error) {
	type expSystemTime struct {
		Current  uint64
		Previous uint64
		Load     float64
	}
	v := expSystemTime{
		Current:  s.curr,
		Previous: s.prev,
		Load:     s.load,
	}
	return json.Marshal(v)
}

type Monitor struct {
	procs            map[uint32]Process
	mu               sync.Mutex
	ord              uint64
	BasicInformation SYSTEM_BASIC_INFORMATION
	cpuTotals        SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
}

// From: procprv.c:#2009
//
// Notes on cycle-based CPU usage:
//
// Cycle-based CPU usage is a bit tricky to calculate because we cannot get the total number of
// cycles consumed by all processes since system startup - we can only get total number of
// cycles per process. This means there are two ways to calculate the system-wide cycle time
// delta:
//
// 1. Each update, sum the cycle times of all processes, and calculate the system-wide delta
//    from this. Process Explorer seems to do this.
// 2. Each update, calculate the cycle time delta for each individual process, and sum these
//    deltas to create the system-wide delta. We use this here.
//
// The first method is simpler but has a problem when a process exits and its cycle time is no
// longer counted in the system-wide total. This may cause the delta to be negative and all
// other calculations to become invalid. Process Explorer simply ignored this fact and treated
// the system-wide delta as unsigned (and therefore huge when negative), leading to all CPU
// usages being displayed as "< 0.01".
//
// The second method is used here, but the adjustments must be done before the main new/modified
// pass. We need take into account new, existing and terminated processes.

func (m *Monitor) updateProcs() error {
	infos, err := QuerySystemProcessInformation()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.procs == nil {
		m.procs = make(map[uint32]Process, 256)
	}
	var cycles uint64
	for _, n := range infos {
		pid := uint32(n.UniqueProcessId)
		p, ok := m.procs[pid]
		if !ok {
			m.procs[pid] = Process{
				Pid:        pid,
				Parent:     uint32(n.InheritedFromUniqueProcessId),
				Name:       n.ImageName.String(),
				CreateTime: n.CreateTime,
				CycleTime:  SystemTime{curr: n.CycleTime},
				UserTime:   SystemTime{curr: uint64(n.UserTime)},
				KernelTime: SystemTime{curr: uint64(n.KernelTime)},
				ord:        m.ord,
			}
		} else {
			p.CycleTime.prev = p.CycleTime.curr
			p.CycleTime.curr = n.CycleTime
			cycles += p.CycleTime.curr - p.CycleTime.prev

			p.UserTime.prev = p.UserTime.curr
			p.UserTime.curr = uint64(n.UserTime)

			p.KernelTime.prev = p.KernelTime.curr
			p.KernelTime.curr = uint64(n.KernelTime)

			p.ord = m.ord
			m.procs[pid] = p
		}
	}

	for k, p := range m.procs {
		if p.ord != m.ord || p.CycleTime.prev == 0 {
			continue
		}
		p.CycleTime.load = (float64(p.CycleTime.curr-p.CycleTime.prev) / float64(cycles)) * 100
		m.procs[k] = p
	}

	return nil
}

type Process struct {
	Pid        uint32
	Parent     uint32
	Name       string
	CreateTime int64
	CycleTime  SystemTime
	UserTime   SystemTime
	KernelTime SystemTime
	ord        uint64
}

type SYSTEM_PROCESS_INFORMATION struct {
	NextEntryOffset              uint32         // ULONG
	NumberOfThreads              uint32         // ULONG
	WorkingSetPrivateSize        int64          // LARGE_INTEGER
	HardFaultCount               uint32         // ULONG
	NumberOfThreadsHighWatermark uint32         // ULONG
	CycleTime                    uint64         // ULONGLONG
	CreateTime                   int64          // LARGE_INTEGER
	UserTime                     int64          // LARGE_INTEGER
	KernelTime                   int64          // LARGE_INTEGER
	ImageName                    UNICODE_STRING // UNICODE_STRING
	BasePriority                 KPRIORITY      // KPRIORITY
	UniqueProcessId              uintptr        // HANDLE
	InheritedFromUniqueProcessId uintptr        // HANDLE
	HandleCount                  uint32         // ULONG
	SessionId                    uint32         // ULONG
	UniqueProcessKey             *uint32        // ULONG_PTR
	PeakVirtualSize              uintptr        // SIZE_T
	VirtualSize                  uintptr        // SIZE_T
	PageFaultCount               uint32         // ULONG
	PeakWorkingSetSize           uintptr        // SIZE_T
	WorkingSetSize               uintptr        // SIZE_T
	QuotaPeakPagedPoolUsage      uintptr        // SIZE_T
	QuotaPagedPoolUsage          uintptr        // SIZE_T
	QuotaPeakNonPagedPoolUsage   uintptr        // SIZE_T
	QuotaNonPagedPoolUsage       uintptr        // SIZE_T
	PagefileUsage                uintptr        // SIZE_T
	PeakPagefileUsage            uintptr        // SIZE_T
	PrivatePageCount             uintptr        // SIZE_T
	ReadOperationCount           int64          // LARGE_INTEGER
	WriteOperationCount          int64          // LARGE_INTEGER
	OtherOperationCount          int64          // LARGE_INTEGER
	ReadTransferCount            int64          // LARGE_INTEGER
	WriteTransferCount           int64          // LARGE_INTEGER
	OtherTransferCount           int64          // LARGE_INTEGER

	// ProcessHacker lists Threads as a field, but it looks like they add it.
	//
	// Threads [1]SYSTEM_THREAD_INFORMATION // SYSTEM_THREAD_INFORMATION
}

type KWAIT_REASON int32

type CLIENT_ID struct {
	UniqueProcess uintptr // HANDLE
	UniqueThread  uintptr // HANDLE
}

type SYSTEM_THREAD_INFORMATION struct {
	KernelTime      int64        // LARGE_INTEGER
	UserTime        int64        // LARGE_INTEGER
	CreateTime      int64        // LARGE_INTEGER
	WaitTime        uint32       // ULONG
	StartAddress    uintptr      // PVOID
	ClientId        CLIENT_ID    // CLIENT_ID
	Priority        KPRIORITY    // KPRIORITY
	BasePriority    int32        // LONG
	ContextSwitches uint32       // ULONG
	ThreadState     uint32       // ULONG
	WaitReason      KWAIT_REASON // KWAIT_REASON
}

/*
func QuerySystemProcessInformation() ([]SYSTEM_PROCESS_INFORMATION, error) {
	const max = 1024 * 1024 * 20

	var p *SYSTEM_PROCESS_INFORMATION
	n := uint32(1024 * 128)
	for i := 0; n < max; i++ {
		b := make([]byte, n)
		p = (*SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&b[0]))
		err := NtQuerySystemInformation(SystemProcessInformation, p, n, &n)
		if err == nil {
			break
		}
		if n < uint32(len(b)) {
			break
		}
		if i >= 10 {
			return nil, fmt.Errorf("ERROR: i: %d n: %d err: %s", i, n, err)
		}
	}

	var infos []SYSTEM_PROCESS_INFORMATION
	for {
		infos = append(infos, *p)
		if p.NextEntryOffset == 0 {
			break
		}
		p = (*SYSTEM_PROCESS_INFORMATION)(add(unsafe.Pointer(p), uintptr(p.NextEntryOffset)))
	}

	return infos, nil
}
*/

/*
func (m *Monitor) updateProcs() error {
	const max = 1024 * 1024 * 100

	var s *SYSTEM_PROCESS_INFORMATION
	n := uint32(1024 * 128)
	for i := 0; n < max; i++ {
		b := make([]byte, n)
		s = (*SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&b[0]))
		err := NtQuerySystemInformation(SystemProcessInformation, s, n, &n)
		if err == nil {
			break
		}
		if n < uint32(len(b)) {
			break
		}
		if i >= 10 {
			return err
		}
		if n > max {
			return err
		}
	}

	m.mu.Lock()
	if m.procs == nil {
		m.procs = make(map[uint32]Process, 256)
	}
	m.ord++
	for i := 0; ; i++ {
		pid := uint32(s.UniqueProcessId)
		p, ok := m.procs[pid]
		if !ok {
			m.procs[pid] = Process{
				Pid:        pid,
				Parent:     uint32(s.InheritedFromUniqueProcessId),
				Name:       s.ImageName.String(),
				CreateTime: s.CreateTime,
				UserTime:   SystemTime{curr: s.UserTime},
				KernelTime: SystemTime{curr: s.KernelTime},
				ord:        m.ord,
			}
		} else {
			// p.UserTime.prev = p.UserTime.curr
			p.UserTime.curr = s.UserTime
			// p.KernelTime.prev = p.KernelTime.curr
			p.KernelTime.curr = s.KernelTime
			p.ord = m.ord
			m.procs[pid] = p
		}
		if s.NextEntryOffset == 0 {
			break
		}
		s = (*SYSTEM_PROCESS_INFORMATION)(add(unsafe.Pointer(s), uintptr(s.NextEntryOffset)))
	}
	for k, p := range m.procs {
		if p.ord != m.ord {
			delete(m.procs, k)
		}
	}
	m.mu.Unlock()

	return nil
}
*/

/*
NTSTATUS WINAPI NtQuerySystemInformation(
  _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
  _Inout_   PVOID                    SystemInformation,
  _In_      ULONG                    SystemInformationLength,
  _Out_opt_ PULONG                   ReturnLength
);
*/

// func NtQuerySystemInformation(SystemInformationClass uint32, SystemInformation uintptr, SystemInformationLength uint32, ReturnLength uint32) {
// 	r1, _, e1 := syscall.Syscall6(procNtQuerySystemInformation.Addr(), 4,
// 		uintptr(SystemInformationClass),
// 		SystemInformation,
// 		uintptr(SystemInformationLength),
// 		uintptr(ReturnLength),
// 		0,
// 		0,
// 	)
// }
