import random

def extract():
    with open('shellcodeCode.exe','rb+') as file:
        with open('shellcode.bin', 'wb+') as save:
            save.write(bytes(file.read()[0x400:0x7D0]))
       
if __name__ == '__main__':
    extract()
