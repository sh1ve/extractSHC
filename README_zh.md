# shc脚本提取
Linux下运行，需要安装好python以及objdump和strings这两个命令，成功运行后会生成一个同名的`.patch`后缀的文件，运行生成的文件，如果一切正常会在标准输出打印原始的脚本内容。

## 使用
```sh
./extractSHC.py [file]

example:
./extractSHC.py test
./test.patch > out.sh
```
