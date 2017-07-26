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
	"sort"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32 = windows.MustLoadDLL("Kernel32.dll") // K32EnumProcesses
	psapi    = windows.MustLoadDLL("Psapi.dll")    // K32EnumProcesses
	ntdll    = windows.MustLoadDLL("Ntdll.dll")    // NtQueryInformationProcess

	procK32EnumProcesses          = kernel32.MustFindProc("K32EnumProcesses")
	procQueryFullProcessImageName = kernel32.MustFindProc("QueryFullProcessImageNameW")

	procGetProcessImageFileName   = psapi.MustFindProc("GetProcessImageFileNameW")
	procNtQueryInformationProcess = ntdll.MustFindProc("NtQueryInformationProcess")
	procNtQuerySystemInformation  = ntdll.MustFindProc("NtQuerySystemInformation")
)

/*
NTSTATUS WINAPI NtQuerySystemInformation(
  _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
  _Inout_   PVOID                    SystemInformation,
  _In_      ULONG                    SystemInformationLength,
  _Out_opt_ PULONG                   ReturnLength
);
*/

func NtQuerySystemInformation(SystemInformationClass uint32, SystemInformation *SYSTEM_PROCESS_INFORMATION,
	SystemInformationLength uint32, ReturnLength *uint32) error {

	const STATUS_SUCCESS = 0x00000000

	r1, _, e1 := syscall.Syscall6(procNtQuerySystemInformation.Addr(), 4,
		uintptr(SystemInformationClass),            // SYSTEM_INFORMATION_CLASS SystemInformationClass
		uintptr(unsafe.Pointer(SystemInformation)), // PVOID                    SystemInformation
		uintptr(SystemInformationLength),           // ULONG                    SystemInformationLength
		uintptr(unsafe.Pointer(ReturnLength)),      // PULONG                   ReturnLength
		0,
		0,
	)
	if r1 != STATUS_SUCCESS {
		if e1 == 0 {
			return syscall.EINVAL
		}
		return e1
	}
	return nil
}

func OpenProcess(pid int) (syscall.Handle, error) {
	const da = syscall.STANDARD_RIGHTS_READ |
		syscall.PROCESS_QUERY_INFORMATION | syscall.SYNCHRONIZE
	h, e := syscall.OpenProcess(da, false, uint32(pid))
	if e != nil {
		return syscall.InvalidHandle, os.NewSyscallError("OpenProcess", e)
	}
	return h, nil
}

func GetProcessImageFileName(h syscall.Handle) (string, error) {
	n := uint32(1024)
	var buf []uint16
	for {
		buf = make([]uint16, n)
		r1, _, e1 := syscall.Syscall(procGetProcessImageFileName.Addr(), 3,
			uintptr(h),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(n),
		)
		if r1 != 0 {
			return string(utf16.Decode(buf[:r1])), nil
		}
		if e1 != syscall.ERROR_INSUFFICIENT_BUFFER {
			return "", os.NewSyscallError("GetProcessImageFileName", e1)
		}
		n += 1024
	}
}

// Slower than GetProcessImageFileName
func QueryFullProcessImageName(h syscall.Handle) (string, error) {
	n := uint32(1024)
	var buf []uint16
	for {
		buf = make([]uint16, n)
		r1, _, e1 := syscall.Syscall6(procQueryFullProcessImageName.Addr(), 4,
			uintptr(h),
			0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&n)),
			0,
			0,
		)
		if r1 != 0 {
			return string(utf16.Decode(buf[:n])), nil
		}
		if e1 != syscall.ERROR_INSUFFICIENT_BUFFER {
			return "", os.NewSyscallError("QueryFullProcessImageName", e1)
		}
	}
}

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
				return nil, os.NewSyscallError("K32EnumProcesses", syscall.EINVAL)
			}
			return nil, os.NewSyscallError("K32EnumProcesses", e1)
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
//   parent
//     child1
//       grandchild1
//       grandchild2
//         great-grandchild1
//     child2
//     child3
//       grandchild1
//     child4
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

/*
func (m *Mgr) serviceDescription(s *mgr.Service) (string, error) {
	var p *windows.SERVICE_DESCRIPTION
	n := uint32(1024)
	for {
		b := make([]byte, n)
		p = (*windows.SERVICE_DESCRIPTION)(unsafe.Pointer(&b[0]))
		err := windows.QueryServiceConfig2(s.Handle,
			windows.SERVICE_CONFIG_DESCRIPTION, &b[0], n, &n)
		if err == nil {
			break
		}
		if err.(syscall.Errno) != syscall.ERROR_INSUFFICIENT_BUFFER {
			return "", err
		}
		if n <= uint32(len(b)) {
			return "", err
		}
	}
	return toString(p.Description), nil
}
*/

func add(p unsafe.Pointer, x uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(p) + x)
}

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

type USTRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
	String        string
	Len           int
}

type byLen []USTRING

func (b byLen) Len() int           { return len(b) }
func (b byLen) Less(i, j int) bool { return b[i].Len < b[j].Len }
func (b byLen) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }

func main() {
	t := time.Now()
	infos, err := QuerySystemProcessInformation()
	if err != nil {
		Fatal(err)
	}

	var us []USTRING
	for _, n := range infos {
		s := n.ImageName.String()
		u := USTRING{
			Length:        n.ImageName.Length,
			MaximumLength: n.ImageName.MaximumLength,
			Buffer:        n.ImageName.Buffer,
			String:        s,
			Len:           len(s),
		}
		u.Len = len(u.String)
		us = append(us, u)

		// fmt.Printf("%q -- %d\n", s, len(s))
	}
	d := time.Since(t)

	// if err := PrintJSON(infos); err != nil {
	// 	Fatal(err)
	// }
	sort.Sort(byLen(us))
	PrintJSON(us)
	fmt.Println("Time:", d, d/time.Duration(len(infos)))
}

func testEnumeProcesses() {

	t := time.Now()
	pids, err := EnumProcesses()
	if err != nil {
		Fatal(err)
	}
	errCount := 0
	for _, pid := range pids {
		h, err := OpenProcess(int(pid))
		if err != nil {
			fmt.Printf("%d: %s\n", pid, err)
			continue
		}
		s, err := GetProcessImageFileName(h)
		// s, err := QueryFullProcessImageName(h)
		if err != nil {
			fmt.Printf("%d: %v - %d\n", pid, err, err.(syscall.Errno))
		} else {
			fmt.Printf("%d: %s\n", pid, filepath.Base(s))
		}

		syscall.CloseHandle(h)
	}
	d := time.Since(t)
	fmt.Println(len(pids), errCount)
	fmt.Println(d, d/time.Duration(len(pids)))
}

/*
func TestSomething() {
	cmd := exec.Command("calc.exe")
	wait := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		time.Sleep(time.Millisecond)
		if err := cmd.Start(); err != nil {
			errCh <- fmt.Errorf("Start: %s", err)
			close(wait)
			return
		}
		close(wait)
		if err := cmd.Wait(); err != nil {
			errCh <- fmt.Errorf("Wait: %s", err)
		}
	}()
	go func() {
		<-wait
		pid := cmd.Process.Pid
		proc, err := os.FindProcess(pid)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		defer proc.Release()
		time.Sleep(time.Millisecond)
		fmt.Println("Killing now..")
		proc.Signal(os.Kill)
		// cmd.Process.Kill()
	}()
	to := time.After(time.Second)
	select {
	case e := <-errCh:
		fmt.Printf("Exited: %v\n", e)
	case <-to:
		fmt.Println("Timout")
	}
}
*/

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

func toString(p *uint16) string {
	if p == nil {
		return ""
	}
	return syscall.UTF16ToString((*[4096]uint16)(unsafe.Pointer(p))[:])
}
