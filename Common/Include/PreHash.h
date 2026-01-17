#pragma once

#define HASH_Kernel32                                           0x30586e87
#define HASH_Ntdll                                              0xd3c8c75f
#define HASH_Kernelbase                                         0x5903a13d

#define HASH_NtAllocateVirtualMemory                            0x8e2f2ede
#define HASH_NtProtectVirtualMemory                             0x24a83a

#define HASH_LoadLibraryA                                       0x7984090d
#define HASH_RtlLookupFunctionEntry                             0x404504db
#define HASH_GetProcAddress                                     0x33e7af71
#define HASH_BaseThreadInitThunk                                0x73936588
#define HASH_RtlUserThreadStart                                 0xd92ef02e

#define HASH_RtlCreateHeap                                      0xf3c767bb
#define HASH_RtlAllocateHeap                                    0x33fef04c

#define HASH_TEXT                                            0xd5bf55ca
#define HASH_RDATA                                           0x8d84f011
#define HASH_DATA                                            0xd5b67e1f
#define HASH_PDATA                                           0x8d60bf0f
#define HASH_RELOC                                           0x8d85aa9a