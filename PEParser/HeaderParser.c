// Copyright (c) 2021 onein528
// Licensed under the MIT License.

#include "PeHeader.h"

WORD BytesArrayToWord(PBYTE pData);

int wmain(void) {

    IMAGE_DOS_HEADER ImageDosHeader = { 0 };

    HANDLE hFile = NULL;
    if ((hFile = CreateFileW(L"C:\\Users\\T31068068\\Desktop\\RegistryParser.exe", GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)) == INVALID_HANDLE_VALUE) {

        wprintf(L"ReadFile failed with 0x%X.\n", GetLastError());
        return FAILURE;
    }

    ParseDosHeader(hFile);


}


BOOL ParseDosHeader(HANDLE hFile) {

    SetFilePointer(hFile, 0x0, NULL, FILE_BEGIN);

    BYTE byReadData[0x40] = { 0 };
    PBYTE pReadedData = NULL;
    DWORD nBaseBlockSize = 0x40;
    DWORD nReadedSize = 0;

    if (ReadFile(hFile, &byReadData, nBaseBlockSize, &nReadedSize, NULL) == FAILURE) {

        wprintf(L"ReadFile failed with 0X%x in ParseImageDosHeader().\n", GetLastError());
        return FAILURE;
    }

    pReadedData = byReadData;

    wprintf(L"Image DOS Header:\n\n  ");

    for (int i = 0; i < 0x40; i++) {
        if (i % 0x10 == 0 && i != 0) wprintf(L"\n  ");
        wprintf(L"%02X ", pReadedData[i]);
    }

    wprintf(L"\n\n");

    wprintf(L"    Magic number:                      0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    Bytes on last page:                0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    pages in file:                     0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    Relocations:                       0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    Size of header:                    0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    Minimum memory:                    0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    Maximum memory:                    0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    Initial SS value:                  0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    Initial SP value:                  0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    Checksum:                          0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    Initial IP value:                  0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    Initial CS value:                  0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    Table offset:                      0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    Overlay number:                    0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    // Reserved1
    pReadedData += 8;

    wprintf(L"    OEM Identifier:                    0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    wprintf(L"    OEM Information:                   0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    // Reserved2
    pReadedData += 20;

    wprintf(L"    PE address:                        0x%04X\n", BytesArrayToWord(pReadedData));

    pReadedData += 2;

    return SUCCESS;
}


BOOL ParseCoffHeader(HANDLE hFile) {

    SetFilePointer(hFile, 0x0, NULL, FILE_BEGIN);

    BYTE byReadData[0x40] = { 0 };
    PBYTE pReadedData = NULL;
    DWORD nBaseBlockSize = 0x40;
    DWORD nReadedSize = 0;

    if (ReadFile(hFile, &byReadData, nBaseBlockSize, &nReadedSize, NULL) == FAILURE) {

        wprintf(L"ReadFile failed with 0X%x in ParseImageDosHeader().\n", GetLastError());
        return FAILURE;
    }

    pReadedData = byReadData;



}



WORD BytesArrayToWord(PBYTE pData) {

    WORD wData = 0;
    BYTE byWordArray[2] = { 0 };

    if (pData == NULL) return FAILURE;

    for (int i = 0; i < 2; i++)byWordArray[i] = pData[i];
    wData = *(WORD*)byWordArray;

    return wData;
}