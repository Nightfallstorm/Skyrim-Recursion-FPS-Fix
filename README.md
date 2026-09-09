# Skyrim Recursion FPS Fix

Fixes FPS lag when a papyrus function gets stuck in a recursion loop 

## Requirements (Linux)
See CLIB-NG [linux cross-compiling](https://github.com/alandtse/CommonLibSSE-NG/blob/ng/examples/linux-cross-compile/README.md)
for one-time setup and instructions

## User Requirements
* [Address Library for SKSE](https://www.nexusmods.com/skyrimspecialedition/mods/32444)
	* Needed for SSE
* [VR Address Library for SKSEVR](https://www.nexusmods.com/skyrimspecialedition/mods/58101)
	* Needed for VR

## Building
```
git clone https://github.com/Nightfallstorm/Skyrim-Recursion-FPS-Fix
cd Skyrim-Recursion-FPS-Fix
cmake -S . -B build \
    --preset build-relwithdebinfo-linux
cmake --build build \
    --preset relwithdebinfo-linux
```

## License
[GPL V3](LICENSE)
