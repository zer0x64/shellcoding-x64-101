# Shellcoding 101 on Linux x86_64

This repo contains exercises for learning shellcoding on linux, on x86_64 architecture(commonly simple called "64 bits").

It is aimed for assembly begginers and doesn't require much skills.
The underlying assembler framework needs build tools and cmake to be installed. Make sure these are installed.

The environment requires Keystone engine, which can be installed using:
```bash
pip3 install --user keystone-engine
```

To compile and run a shellcode, run:
```bash
python3 shellcode.py example.asm
```

To debug a shellcode, make sure it contains a brakpoint(int3) and run the following command:
```bash
gdb --args python3 shellcode.py example.asm
```

The presentation can be found at the following link:
https://docs.google.com/presentation/d/1xvIIQhMaD04_eui1VNbddBf7HwdWtgrsTbdqOlb0ao4/edit?usp=sharing
