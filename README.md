# PE Export Walker

This project is a small Windows C program that loads `kernel32.dll` from disk, validates it as a PE file, and enumerates the exported functions found in the PE export table.

It is intended as a learning example for Windows PE parsing and DLL export inspection.

## What it does

The program:

- Opens `C:\Windows\System32\kernel32.dll` using `CreateFileA`
- Reads the file into memory
- Validates the DOS and NT headers
- Confirms that the binary is a 64-bit PE
- Locates the export directory
- Walks the export address table and name table
- Prints exported function names and their RVA/ordinal information

## Project purpose

This project demonstrates how to work with the Portable Executable (PE) format on Windows, including:

- PE header validation
- Parsing `IMAGE_EXPORT_DIRECTORY`
- Resolving export names, ordinals, and RVAs
- Reading metadata from a DLL without importing it at runtime

## Requirements

- Windows operating system
- A C compiler such as Microsoft Visual Studio's `cl.exe`
- A 64-bit PE file target (the code checks for `IMAGE_NT_OPTIONAL_HDR64_MAGIC`)

## Build

Open a Developer Command Prompt for Visual Studio and run:

```bat
cl /nologo eat_walker.c /EHsc /Fe:pe_export_walker.exe
```

Alternatively, compile with your preferred Windows C toolchain, provided it supports Win32 API headers.

## Run

```bat
pe_export_walker.exe
```

The program will print entries similar to:

```text
[+] Valid PE loaded into memory
  1  0x00000000  ...
  2  0x00000000  ...
```

## Notes

- This is primarily an educational project and is not a production-safe PE parser.
- The code intentionally targets a known Windows system DLL for demonstration.
- It parses the export table in memory and prints exported names along with ordinal and RVA data.

## Important

This kind of code is commonly used for reverse engineering and low-level Windows binary analysis. Use it only for legitimate learning, security research, and authorized testing.
