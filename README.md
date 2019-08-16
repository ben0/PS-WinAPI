# PS-WinAPI
PowerShell Windows API stuff

## Managed to unmanaged conversion

| Unmanaged (Windows API) | Managed (.Net / PS)| Information |
|-----------|---------|----------|
| bool | bool| Boolean value - true or false |
| byte | byte| Single byte 0x00 - 0xff |
| char, wchar | char| Single character - one byte |
| double | double | Decimal numbers |
| handle,hfile,hinstance,lpvoid | intptr | 4 or 8 bytes integer |
| lpcwstr,lpcstr,lpstr,lpwstr,pcstr,pcwstr,pstr,pcwstr | string | 
| int,int32 | int | Integer  -2,147,483,648 - 2,147,483,647 |
| uint | uint | Unsigned integer 0 - 4,297,???,??? |
| short | short | 2 bytes -32768 to 32767 |
| ushort | ushort | Unsigned short 0 - 65535 |
| long,word | long | 2 byte integer |
| dword,uint64 | ulong | Double word 8 bytes | 
| lpcvoid,void | void | ??? |
