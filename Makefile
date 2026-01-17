#Makefile

CC_X64	= x86_64-w64-mingw32-gcc

CFLAGS = -m64 -falign-jumps=1 -falign-labels=1 -nostdlib -ffunction-sections
CFLAGS := $(CFLAGS) -fpack-struct=8 -fno-ident -fno-asynchronous-unwind-tables
CFLAGS := $(CFLAGS) -Wconversion -Os -Wl,-e,EntryPoint -fPIC -Wl,--image-base=0
CFLAGS := $(CFLAGS) -Wl,-s,--no-seh -w -masm=intel

OUTPUT_BEACON_EXE	:=	Bin/rdll_beacon.exe 
OUTPUT_BEACON_SH	:=	Bin/rdll_beacon.bin 

OUTPUT_POSTEX_EXE	:=	Bin/rdll_postex.exe
OUTPUT_POSTEX_SH	:=	Bin/rdll_postex.bin 

COMMON_INCLUDE	:= 	Common/Src/*.c Bin/temp/*.o -I./Common/Include
BEACON_INCLUDE	:=	$(COMMON_INCLUDE) -I./Beacon/Include 
POSTEX_INCLUDE	:=	$(COMMON_INCLUDE) -I./Postex/Include 

.PHONY: all common beacon postex extract cleanup

all: common beacon postex extract cleanup
common:
	@ nasm -f win64 Common/Asm/Eaf.s -o Bin/temp/Eaf.o 
	@ nasm -f win64 Common/Asm/End.s -o Bin/temp/End.o 
	@ nasm -f win64 Common/Asm/Entry.s -o Bin/temp/Entry.o 
	@ nasm -f win64 Common/Asm/Utils.s -o Bin/temp/Utils.o 
	
beacon:
	@ $(CC_X64) Beacon/Src/*.c $(BEACON_INCLUDE) $(CFLAGS) -o $(OUTPUT_BEACON_EXE)

postex:
	@ $(CC_X64) Postex/Src/*.c  $(POSTEX_INCLUDE) $(CFLAGS) -o $(OUTPUT_POSTEX_EXE) 

extract:
	@ python3 Utils/Extract.py -f $(OUTPUT_BEACON_EXE) -o $(OUTPUT_BEACON_SH)
	@ python3 Utils/Extract.py -f $(OUTPUT_POSTEX_EXE) -o $(OUTPUT_POSTEX_SH)

cleanup:
	@ rm Bin/temp/*.o 
	@ rm $(OUTPUT_BEACON_EXE)
	@ rm $(OUTPUT_POSTEX_EXE)
	@ echo "Reflective loader ready !"
