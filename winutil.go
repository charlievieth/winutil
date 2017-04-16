// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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

type uint32Slice []uint32

func (p uint32Slice) Len() int           { return len(p) }
func (p uint32Slice) Less(i, j int) bool { return p[i] < p[j] }
func (p uint32Slice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

type Process struct {
	Pid      uint32
	Parent   *Process
	Children map[uint32]*Process
}

func sortPids(p []uint32) {
	n := len(p)
	for i := n - 1; i > 0; i-- {
		if p[i] < p[i-1] {
			fmt.Println("sortPids: not sorted")
			sort.Sort(uint32Slice(p))
			return
		}
	}
	fmt.Println("sortPids: sorted")
}

type expProcess struct {
	Pid      uint32
	Parent   uint32
	Children []expProcess
}

func (p *Process) ToJSON() expProcess {
	x := expProcess{Pid: p.Pid}
	if p.Parent != nil {
		x.Parent = p.Parent.Pid
	}
	if len(p.Children) != 0 {
		for _, c := range p.Children {
			x.Children = append(x.Children, c.ToJSON())
		}
	}
	return x
}

func CreateTree() (*Process, error) {
	pids, err := EnumProcesses()
	if err != nil && len(pids) == 0 {
		return nil, err
	}
	sortPids(pids)

	// sanity check
	if pids[0] != 0 {
		panic("CreateTree: missing PID 0 from process list")
	}
	if len(pids) == 1 {
		panic("CreateTree: failed to enumerate process")
	}
	if pids[1] == 0 {
		panic("CreateTree: duplicate PID 0 entry in process list")
	}

	// manually add PID 0
	procs := make(map[uint32]*Process, len(pids))
	head := &Process{
		Pid:    0,
		Parent: nil,
	}
	procs[head.Pid] = head

	for _, pid := range pids[1:] {
		ppid, err := ParentPID(pid)
		if err != nil {
			fmt.Printf("CreateTree (%d): %s\n", pid, err)
			continue
		}
		pp, ok := procs[ppid]
		if !ok {
			pp = &Process{
				Pid:      ppid,
				Children: make(map[uint32]*Process),
			}
			procs[ppid] = pp
		}
		if pp.Children == nil {
			pp.Children = make(map[uint32]*Process)
		}
		cp, ok := procs[pid]
		if !ok {
			cp = &Process{
				Pid:    pid,
				Parent: pp,
			}
			procs[pid] = cp
		}
		if cp.Parent == nil {
			cp.Parent = pp
		}
		pp.Children[pid] = cp
	}

	return head, nil
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

const (
	PROCESS_QUERY_INFORMATION = 0x00000400
	PROCESS_VM_READ           = 0x0010
)

// ParentPID returns the parent pid of pid.
//
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684280(v=vs.85).aspx
func ParentPID(pid uint32) (uint32, error) {
	const (
		ProcessBasicInformation = 0
		da                      = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
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
func appendChildren(a []uint32, parent uint32, m map[uint32][]uint32) []uint32 {
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
		panic("appendChildren: too many pids - cyclical loop is likely cause")
	}

	return a
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
func RecursiveKill(parent int) (first error) {
	ppid := uint32(parent)

	// make sure we can kill the parent
	p, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, ppid)
	if err != nil {
		return err
	}
	syscall.CloseHandle(p)

	m, err := parentProcesses()
	if err != nil && len(m) == 0 {
		return err
	}
	pids := appendChildren([]uint32{ppid}, ppid, m)
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
	err = RecursiveKill(parent)
	d := time.Since(t)

	fmt.Println(d)
	fmt.Println("error:", err)
}

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

// func main() {
// 	if len(os.Args) != 2 {
// 		fmt.Fprintln(os.Stderr, "Invalid args...")
// 	}
// 	parent, err := strconv.Atoi(os.Args[1])
// 	if err != nil {
// 		fmt.Fprintln(os.Stderr, err)
// 	}
// 	if err := RecursiveKill(parent); err != nil {
// 		fmt.Fprintln(os.Stderr, err)
// 	}
// }

/*
// appendChildren recursively appends the child pids of parent pid to slice a.
func appendChildren(a []uint32, parent uint32, m map[uint32][]uint32) []uint32 {
	if pids, ok := m[parent]; ok && len(pids) != 0 {
		// Add children first
		a = append(a, pids...)
		// Add grandchildren, if any...
		for _, pid := range pids {
			// WARN (CEV): not tested - attempt to prevent infinite loop
			if pid != parent {
				a = appendChildren(a, pid, m)
			}
		}
	}
	return a
}
*/
