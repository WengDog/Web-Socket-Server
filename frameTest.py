import sys
import struct

class Frame :
    def __init__(self,FIN,RSV,OPCODE,MASK,PLLENGTH,MASKKEY,PL):
        self.FIN = FIN
        self.RSV = RSV
        self.OPCODE = OPCODE
        self.MASK = MASK
        self.PLLENGTH = PLLENGTH
        self.MASKKEY = MASKKEY
        self.PL = PL
        self.CHECKSUM = Frame.makeChecksum(self)

    def makeChecksum(self):
        SUM = self.FIN + self.RSV + self.OPCODE + self.MASK + self.PLLENGTH + self.MASKKEY + self.PL
        check = int.from_bytes(SUM[0:2],byteorder ='big')

        for i in range (2,len(SUM)-2,2) :
            NextCheck = int.from_bytes(SUM[i:i+2],byteorder='big')
            check = (check ^ NextCheck)

        check = format(check, "08b")
        CHECKSUM = int(check,2).to_bytes(2, "big")
        return(CHECKSUM)

    def encode(self) :
        return(self.FIN + self.RSV + self.OPCODE + self.MASK + self.PLLENGTH + self.MASKKEY + self.PL)