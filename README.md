# garlic-worker

PS4 and PS5 save processing worker for [garlicsaves.com](https://garlicsaves.com). Handles decrypt, encrypt, resign, and re-region operations on jailbroken consoles.

## PC worker

The standalone `../SaveStudio-PC` project contains the C++17 SaveStudio CLI and Linux HTOS TCP worker. See `../SaveStudio-PC/README.md` for build, configuration, verification, and current limitations. It advertises only PS5 decrypt and encrypt jobs; console workers remain responsible for the other operations.

## Credits

- [@c0w-ar](https://github.com/c0w-ar) for reverse engineering the PS5 save process
- [@hzhreal](https://github.com/hzhreal) for making HTOS
- [@Team-Alua](https://github.com/Team-Alua) for cecie.nim

