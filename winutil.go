// +build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                      = windows.MustLoadDLL("Kernel32.dll") // K32EnumProcesses
	ntdll                         = windows.MustLoadDLL("Ntdll.dll")    // NtQueryInformationProcess
	procK32EnumProcesses          = kernel32.MustFindProc("K32EnumProcesses")
	procNtQueryInformationProcess = ntdll.MustFindProc("NtQueryInformationProcess")
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682629(v=vs.85).aspx
func EnumProcesses() ([]uint32, error) {
	const MaxPids = 1048576 // 0x100000
	var (
		count int
		pids  []uint32
		size  uint32
		read  uint32
	)
	for count = 128; count < MaxPids && read == size; count *= 2 {
		pids = make([]uint32, count)
		size = uint32(unsafe.Sizeof(pids[0]) * uintptr(len(pids)))
		r1, _, e1 := syscall.Syscall(procK32EnumProcesses.Addr(), 3,
			uintptr(unsafe.Pointer(&pids[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&read)),
		)
		if r1 == 0 {
			if e1 == 0 {
				return nil, syscall.EINVAL
			}
			return nil, e1
		}
	}
	if count >= MaxPids {
		return nil, fmt.Errorf("EnumProcess: process count exceeds limit: %d", MaxPids)
	}
	n := read / uint32(unsafe.Sizeof(pids[0]))
	return pids[:n], nil
}

// _PROCESS_BASIC_INFORMATION
//
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684280(v=vs.85).aspx
type ntPROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr    // ExitStatus
	PebBaseAddress  uintptr    // PebBaseAddress
	Reserved2       [2]uintptr // {AffinityMask, BasePriority}
	UniqueProcessId uintptr    // UniqueProcessId
	Reserved3       uintptr    // InheritedFromUniqueProcessId
}

// ParentPID returns the parent pid of pid.
//
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684280(v=vs.85).aspx
func ParentPID(pid uint32) (uint32, error) {
	const (
		ProcessBasicInformation = 0
		PROCESS_VM_READ         = 0x0010
		da                      = syscall.PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
	)
	if pid == 0 {
		return 0, nil
	}
	h, err := windows.OpenProcess(da, false, pid)
	if err != nil {
		if err == windows.ERROR_ACCESS_DENIED {
			return 0, nil
		}
		return 0, err
	}
	var pbi ntPROCESS_BASIC_INFORMATION
	var length uint32
	r1, _, e1 := syscall.Syscall6(procNtQueryInformationProcess.Addr(), 5,
		uintptr(h),
		ProcessBasicInformation,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&length)),
		0,
	)
	windows.CloseHandle(h)
	if r1 != 0 {
		if e1 == 0 {
			return 0, syscall.EINVAL
		}
		return 0, e1
	}
	if pbi.Reserved3 > math.MaxUint32 {
		return 0, syscall.EINVAL
	}
	return uint32(pbi.Reserved3), nil
}

// parentProcesses returns a map of parent to child pids (parent => []children)
func parentProcesses() (parentChild map[uint32][]uint32, first error) {
	pids, err := EnumProcesses()
	if err != nil {
		return nil, err
	}
	for _, p := range pids {
		parent, err := ParentPID(p)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if parentChild == nil {
			parentChild = make(map[uint32][]uint32, len(pids))
		}
		parentChild[parent] = append(parentChild[parent], p)
	}
	return
}

// appendChildren, appends the child pids of parent pid to slice a.
func appendChildren(a []uint32, parent uint32, m map[uint32][]uint32) ([]uint32, error) {
	const MaxPids = 1048576 // 0x100000
	stack := []uint32{parent}

	// do this without recursion in case our input contains
	// cyclical references
	for len(stack) > 0 && len(a) < MaxPids {
		ppid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if pids, ok := m[ppid]; ok && len(pids) != 0 {
			// skip duplicate pid (this can happen with pid 0)
			if len(a) != 0 && a[0] == pids[0] {
				pids = pids[1:]
			}
			// Add children first
			a = append(a, pids...)

			// Add grandchildren, if any...
			for _, pid := range pids {
				if pid != parent {
					stack = append(stack, pid)
				}
			}
		}
	}
	if len(a) >= MaxPids {
		return nil, errors.New("appendChildren: too many pids - cyclical loop is likely cause")
	}
	return a, nil
}

// ChildPids returns the child pids of parent ppid, including ppid.
func ChildPids(ppid uint32) ([]uint32, error) {
	// ignore error - likely Access is Denied
	m, err := parentProcesses()
	if err != nil && len(m) == 0 {
		return nil, err
	}
	return appendChildren([]uint32{ppid}, ppid, m)
}

func terminateProcess(pid, exitcode uint32) error {
	h, e := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, pid)
	if e != nil {
		return e
	}
	e = syscall.TerminateProcess(h, exitcode)
	syscall.CloseHandle(h)
	return e
}

// RecursiveKill, kills the parent pid and its children in breadth-first
// order: parent -> child -> grandchild -> etc...
//
// Note: child pids created while this running will be missed.
func RecursiveKill(ppid uint32) (first error) {
	// make sure we can kill the parent
	p, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, ppid)
	if err != nil {
		return err
	}
	syscall.CloseHandle(p)

	// ignore error if some processes are returned
	m, err := parentProcesses()
	if err != nil && len(m) == 0 {
		return err
	}

	// don't ignore this error
	pids, err := appendChildren([]uint32{ppid}, ppid, m)
	if err != nil {
		return err
	}

	for _, child := range pids {
		err := terminateProcess(child, 1)
		if err != nil && first == nil {
			first = err
		}
	}

	return first
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Invalid args...")
	}

	parent, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	t := time.Now()
	err = RecursiveKill(uint32(parent))
	d := time.Since(t)

	fmt.Println(d)
	fmt.Println("error:", err)
}

// WARN: Dev only helper functions

func PrintJSON(v interface{}) error {
	b, err := json.MarshalIndent(v, "", "    ")
	if err == nil {
		fmt.Println(string(b))
	}
	return err
}

func Fatal(err interface{}) {
	if err == nil {
		return
	}
	_, file, line, ok := runtime.Caller(1)
	if ok {
		file = filepath.Base(file)
	}
	switch err.(type) {
	case error, string, fmt.Stringer:
		if ok {
			fmt.Fprintf(os.Stderr, "Error (%s:%d): %s\n", file, line, err)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		}
	default:
		if ok {
			fmt.Fprintf(os.Stderr, "Error (%s:%d): %#v\n", file, line, err)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %#v\n", err)
		}
	}
	os.Exit(1)
}
