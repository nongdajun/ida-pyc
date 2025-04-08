# ida-pyc

**".pyc"  python compiled byte code analysis  plugin for IDA Pro.**

* tested on  IDA Pro 9.0,  xdis==6.1.3,  uncompyle6==3.9.2

* support python compiled bytecode version from  python1 to python3 (the same as 'xdis' does)

* has more features (like jump xref, ...) for python3 compiled  bytecode  (more older versions will be add if ...)

  

### Installation

1. install the depends （under the python enviroment config for ida pro）

   ```python
   pip install xdis
   pip install uncompyle6
   ```

   

2. copy files to IDA Pro directories

```bash
cp loaders/pyc-loader.py  ${YOU_IDA_HOME_DIR}/loaders/
cp procs/pyc-proc.py  ${YOU_IDA_HOME_DIR}/procs/
cp -r procs/pyc-procs  ${YOU_IDA_HOME_DIR}/procs/
```



### Usage

![image-20250402095555846](imgs/image-20250402095555846.png)

![image-20250402095755641](imgs/image-20250402095755641.png)

![image-20250407095020194](imgs/image-20250407095020194.png)

**press 'Ctrl+F5' or 'Alt+F5' to decompile the pyc file**

**press 'e' or 'double click' to patch the code**

