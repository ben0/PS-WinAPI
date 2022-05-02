# PS-WinAPI
PowerShell Windows API stuff

## Managed to unmanaged conversion

| Unmanaged (Windows API) | Managed (.Net / PS)| Info |
|-----------|---------|----------|
| bool | bool (System.Boolean) | Boolean value - true or false  |
| byte | byte (System.Byte) | Single byte 0x00 - 0xff (0-255) |
| char, wchar | char (System.Char) | Single character - 2 bytes (U +0000 - U +ffff) |
| double | double (System.Double) | Floating point numbers 64bits |
| handle,hfile,hinstance,lpvoid | intptr | 4 or 8 bytes integer |
| lpcwstr,lpcstr,lpstr,lpwstr,pcstr,pcwstr,pstr,pcwstr | string (System.String) | Reference type variable |
| int,int32 | int | Integer  -2,147,483,648 - 2,147,483,647 |
| uint | uint | Unsigned integer 0 - 4,297,???,??? |
| short | short (System.Int16)| 2 bytes -32768 to 32767 |
| ushort | ushort | Unsigned short 0 - 65535 |
| long,word | long | 2 byte integer |
| dword,uint64 | ulong | Double word 8 bytes | 
| lpcvoid,void | void | ??? |
| Unmanaged | managed | info |
| char | sbyte	| System.Sbyte signed integer |
| short int | short	| System.Int16 signed integer |
| int | Int	| System.Int32 signed integer |
| __int64 | long | System.Int64 signed integer |
| ??? | byte | System.byte unsigned integer |
| ushort | System.UInt16 unsigned integer |
| uint | System.UInt32 unsigned integer |
| ulong | System.UInt64 unsigned integer |
| float | System.Single 32 |
| double | System.Double 64 |
| decimal | System.Decimal 128 |
| char | System.Char 16 - U +0000 to U +ffff |
| bool | System.Boolean	True / False |


From: https://docs.microsoft.com/en-us/archive/msdn-magazine/2003/july/net-column-calling-win32-dlls-in-csharp-with-p-invoke

| Win32 Types |	Specification |	CLR Type |
|-----------|---------|----------|
|char, INT8, SBYTE, CHARâ€ |8-bit signed integer |	System.SByte|
|short, short int, INT16, SHORT |	16-bit signed integer	| System.Int16|
|int, long, long int, INT32, LONG32, BOOLâ€ , INT |	32-bit signed integer |	System.Int32|
|__int64, INT64, LONGLONG	| 64-bit signed integer |	System.Int64|
|unsigned char, UINT8, UCHARâ€ , BYTE	| 8-bit unsigned integer | System.Byte|
|unsigned short, UINT16, USHORT, WORD, ATOM, WCHARâ€ , __wchar_t |	16-bit unsigned integer |	System.UInt16|
|unsigned, unsigned int, UINT32, ULONG32, DWORD32, ULONG, DWORD, UINT |	32-bit unsigned integer	| System.UInt32|
|unsigned __int64, UINT64, DWORDLONG, ULONGLONG	| 64-bit unsigned integer	| System.UInt64|
|float, FLOAT |	Single-precision floating point |	System.Single|
|double, long double, DOUBLE	| Double-precision floating point | System.Double|
In Win32 this type is an integer with a specially assigned meaning; in contrast, the CLR provides a specific type devoted to this meaning.
