import pydffi
from rsakey import RSAKey
from tools import int_from_bytes, int_to_bytes

F = pydffi.FFI()
CU = F.compile('''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define RSAENH_PKC_BLOCKTYPE           0x02
bool unpad_data(const uint8_t *abData, unsigned dwDataLen, uint8_t *abBuffer, unsigned*dwBufferLen)
{
    unsigned i;

    if (dwDataLen < 3) {
        return false ;
    }    
    for (i=2; i<dwDataLen; i++) 
        if (!abData[i])
            break;

    if ((i == dwDataLen) || (*dwBufferLen < dwDataLen - i - 1) ||
        (abData[0] != 0x00) || (abData[1] != RSAENH_PKC_BLOCKTYPE))
    {
        return false;
    }    

    *dwBufferLen = dwDataLen - i - 1; 
    memmove(abBuffer, abData + i + 1, *dwBufferLen);
    return true;
}
''')

def CryptImportKey(data):
    ret = RSAKey(data)
    if not ret.valid:
        return None
    return ret

def CryptDecrypt(rsakey, data):
    data = int_from_bytes(data, "little")
    data = pow(data, rsakey.d, rsakey.N)
    data = bytearray(int_to_bytes(data, rsakey.keylen, "big"))
    newlen = F.UInt(len(data))
    if not CU.funcs.unpad_data(data, len(data), data, F.ptr(newlen)):
        return None
    return data[:int(newlen)]
