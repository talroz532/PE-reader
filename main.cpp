#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include "parser.h"



int main() {
	const char* filePath = "";

	if (!*filePath)
	{
		printf("No file was declared!\n");
		return -1;
	}

	FILE* fptr;
	fptr = fopen(filePath, "rb");
	if (fptr == NULL )
	{
		printf("error opening the file!");
		return -1;
	}

	//size of file
	fseek(fptr, 0, SEEK_END);
	size_t fileSize = ftell(fptr)/1024;

	printf("\n\t\t==INFOMARTION==\nfile size: %d KB\n\n", fileSize);

	//IMAGE DOS HEADER
	fseek(fptr, 0, SEEK_SET);
	fread_s(&DosHeader, sizeof(IMAGE_DOS_HEADER), sizeof(IMAGE_DOS_HEADER), 1, fptr);

	if (DosHeader.e_magic != 0x5a4d)
	{
		printf("error! this is not MZ file");
		fclose(fptr);
		return -1;
	}
	
	printf("\t\t==IMAGE DOS HEADER==\n\n");
	printf("e_magic:    0x%08X \n", DosHeader.e_magic);
	printf("e_cblp:	    0x%08X \n", DosHeader.e_cblp);
	printf("e_cp:	    0x%08X \n", DosHeader.e_cp);
	printf("e_crlc:	    0x%08X \n", DosHeader.e_crlc);
	printf("e_cparhdr:  0x%08X \n", DosHeader.e_cparhdr);
	printf("e_minalloc: 0x%08X \n", DosHeader.e_minalloc);
	printf("e_maxalloc: 0x%08X \n", DosHeader.e_maxalloc);
	printf("e_ss:	    0x%08X \n", DosHeader.e_ss);
	printf("e_sp:	    0x%08X \n", DosHeader.e_sp);
	printf("e_ip:	    0x%08X \n", DosHeader.e_ip);
	printf("e_cs:	    0x%08X \n", DosHeader.e_cs);
	printf("e_lfarlc:   0x%08X \n", DosHeader.e_lfarlc);
	printf("e_ovno:     0x%08X \n", DosHeader.e_ovno);
	printf("e_res:	    0x%08p \n", DosHeader.e_res);
	printf("e_oemid:    0x%08X \n", DosHeader.e_oemid);
	printf("e_oeminfo:  0x%08X \n", DosHeader.e_oeminfo);
	printf("e_res2:     0x%08p \n", DosHeader.e_res2);
	printf("e_lfanew:   0x%08X \n\n", DosHeader.e_lfanew);
	
	//IMAGE NT HEADER
	fseek(fptr, DosHeader.e_lfanew, SEEK_SET);
	fread_s(&NTHeader, sizeof(IMAGE_NT_HEADERS), sizeof(IMAGE_NT_HEADERS), 1, fptr);

	printf("\t\t==IMAGE NT HEADER==\n");
	printf("Signature: %08X \n\n", NTHeader.Signature);

	//IMAGE FILE HEADER
	fread_s(&FileHeader, sizeof(IMAGE_FILE_HEADER), sizeof(IMAGE_FILE_HEADER), 1, fptr);

	printf("\t\t==IMAGE FILE HEADER==\n");
	printf("Machine:              0x%08X \n", FileHeader.Machine);
	printf("NumberOfSections:     0x%08X \n", FileHeader.NumberOfSections);
	printf("TimeDateStamp:        0x%08X \n", FileHeader.TimeDateStamp);
	printf("PointerToSymbolTable: 0x%08X \n", FileHeader.PointerToSymbolTable);
	printf("NumberOfSymbols:      0x%08X \n", FileHeader.NumberOfSymbols);
	printf("SizeOfOptionalHeader: 0x%08X \n", FileHeader.SizeOfOptionalHeader);
	printf("Characteristics:      0x%08X \n\n", FileHeader.Characteristics);


	//IMAGE OPTIONAL HEADER
	fread_s(&OptinalHeader, sizeof(IMAGE_OPTIONAL_HEADER), sizeof(IMAGE_OPTIONAL_HEADER), 1, fptr);
	printf("\t\t==IMAGE OPTIONAL HEADER==\n");
	printf("Magic:                       0x%08X \n", OptinalHeader.Magic);
	printf("MajorLinkerVersion:          0x%08X \n", OptinalHeader.MajorLinkerVersion);
	printf("SizeOfCode:                  0x%08X \n", OptinalHeader.SizeOfCode);
	printf("SizeOfInitializedData:       0x%08X \n", OptinalHeader.SizeOfInitializedData);
	printf("SizeOfUninitializedData:     0x%08X \n", OptinalHeader.SizeOfUninitializedData);
	printf("AddressOfEntryPoint:         0x%08X \n", OptinalHeader.AddressOfEntryPoint);
	printf("BaseOfCode:                  0x%08X \n", OptinalHeader.BaseOfCode);
	printf("BaseOfData:                  0x%08X \n", OptinalHeader.BaseOfData);
	printf("ImageBase:                   0x%08X \n", OptinalHeader.ImageBase);
	printf("SectionAlignment:            0x%08X \n", OptinalHeader.SectionAlignment);
	printf("FileAlignment:               0x%08X \n", OptinalHeader.FileAlignment);
	printf("MajorOperatingSystemVersion: 0x%08X \n", OptinalHeader.MajorOperatingSystemVersion);
	printf("MajorImageVersion:           0x%08X \n", OptinalHeader.MajorImageVersion);
	printf("MajorSubsystemVersion:       0x%08X \n", OptinalHeader.MajorSubsystemVersion);
	printf("Win32VersionValue:           0x%08X \n", OptinalHeader.Win32VersionValue);
	printf("SizeOfImage:                 0x%08X \n", OptinalHeader.SizeOfImage);
	printf("SizeOfHeaders:               0x%08X \n", OptinalHeader.SizeOfHeaders);
	printf("CheckSum:                    0x%08X \n", OptinalHeader.CheckSum);
	printf("Subsystem:                   0x%08X \n", OptinalHeader.Subsystem);
	printf("DllCharacteristics:          0x%08X \n", OptinalHeader.DllCharacteristics);
	printf("SizeOfStackReserve:          0x%08X \n", OptinalHeader.SizeOfStackReserve);
	printf("SizeOfStackCommit:           0x%08X \n", OptinalHeader.SizeOfStackCommit);
	printf("SizeOfHeapReserve:           0x%08X \n", OptinalHeader.SizeOfHeapReserve);
	printf("SizeOfHeapCommit:            0x%08X \n", OptinalHeader.SizeOfHeapCommit);
	printf("LoaderFlags:                 0x%08X \n", OptinalHeader.LoaderFlags);
	printf("NumberOfRvaAndSizes:         0x%08X \n", OptinalHeader.NumberOfRvaAndSizes);


	fclose(fptr);
	return 0;
}
