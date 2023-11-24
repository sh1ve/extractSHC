# extractSHC

This tool needs to run on the Linux. You should have the `readelf`, `objdump`, and `strings` commands installed in advance to use extractSHC. After a successful run, it will generate a new file with the same name and a `.patch` extension. Add execution permissions to it and run. During normal execution, the standard output will print the original script, and any standard error output will print a message ending with <null>.


## Usage
```sh
./extractSHC.py [file]

example:
./extractSHC.py test
chmod +x test.patch
./test.patch > out.sh
```

## TODO

patch `HARDENING`