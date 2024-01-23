# extractSHC

This tool needs to run on the Linux. You should have the `objdump` and `strings` commands installed in advance to use extractSHC. After a successful run, it will generate a new file with the same name and a `.patch` extension. Run the file. During normal execution, the standard output will print the original script.


## Usage
```sh
./extractSHC.py [file]

example:
./extractSHC.py test
./test.patch > out.sh
```
