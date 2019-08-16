# PS-WinAPI
PowerShell Windows API stuff

## Managed to unmanaged conversion

| Unmanaged (Windows API) | Managed (.Net / PS)|
|-----------|---------|
|bool | bool|
|byte | byte|
|char,wchar | char|
|double | double|
|int,int32 | int|
|handle,hfile,hinstance,lpvoid | intptr|
|long,word | long|
|short | short|
|lpcwstr,lpcstr,lpstr,lpwstr,pcstr,pcwstr,pstr,pcwstr | string|
|uint | unit|
|dword,uint64 | ulong|
|ushort | ushort|
|lpcvoid,void | void|
