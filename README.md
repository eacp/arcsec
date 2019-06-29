# Arcsek. Archive Secretly
A package for creating anecrypted archives using gzip compression. 
I thought it look cooler with a k at the end

The purpose of this package/library is to allow the creation of encrypted archives composed of many,
probably large, files (like images or video). It takes care of not loading the whole files in memory since
they can be very large and we might run out of memory.

## Testing and large files
You can test this package as any other Go package/module by using `go test`. The tests are
configured to use every file in the `testing-files/in` directory. You can add large files
there and they will be taken into account.

### Testing with limited memory
What I did to test if the package works with limited memory was to open 10 chrome tabs in a variety of
sites and then place a pair of 4k videos in `testing-files/in` which together are around 2 GB long, and I edited
the project on GoLand (based in IntelliJ) which itself uses some amount of memory. This way I made sure
the files are not been held in memory and it works for large amounts of data.

## Known issues
The packages relies on temporal files instead of memory in order to not consume the whole ram when encrypting
large folders. The files are eventually deleted whe calling the `Close()` function. This might open the library
to side channel attacks when the archive is being created. Whoever, that does not affect the resulting archive
if it is transfered to another locatin (like a USB drive for instance)
