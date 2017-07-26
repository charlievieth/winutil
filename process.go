// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"unicode/utf16"
	"unsafe"
)

type ProcessTime struct {
	Pid    uint32
	user   SystemTime
	kernel SystemTime
	idle   SystemTime
}

type Monitor struct {
	pids map[uint32]*ProcessTime
}

type SystemTime struct {
	previous uint64
	load     float64
}

type Process struct {
	Pid    int
	name   string
	handle uintptr
}

type Tree struct {
	Pid      int
	Parent   *Tree
	Children []*Tree
}

const (
	SystemBasicInformation                = 0
	SystemPerformanceInformation          = 2
	SystemTimeOfDayInformation            = 3
	SystemProcessInformation              = 5
	SystemProcessorPerformanceInformation = 8
	SystemInterruptInformation            = 23
	SystemExceptionInformation            = 33
	SystemRegistryQuotaInformation        = 37
	SystemLookasideInformation            = 45
	SystemPolicyInformation               = 134
)

// Use: SystemProcessorPerformanceInformation
type SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION struct {
	IdleTime       int64  // LARGE_INTEGER
	KernelTime     int64  // LARGE_INTEGER
	UserTime       int64  // LARGE_INTEGER
	DpcTime        int64  // LARGE_INTEGER
	InterruptTime  int64  // LARGE_INTEGER
	InterruptCount uint32 // ULONG
}

type KPRIORITY int32

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

func (u UNICODE_STRING) String() string {
	if u.Length == 0 || u.MaximumLength == 0 || u.Buffer == nil {
		return ""
	}
	// This really shouldn't be possible
	if u.Length&1 == 1 {
		panic(fmt.Sprintf("UNICODE_STRING: odd length: %d", u.Length))
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

	// ProcessHacker lists Threads as a field,
	// but it looks like they add it.
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
