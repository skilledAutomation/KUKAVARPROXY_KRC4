"""
    Author: Davide Rosa
    Description: Client application for KUKAVARPROXY for KRC4
"""

import struct
import socket
import time
import traceback
import os
import select

class KukaVarProxyClient():
    sock = None
    host = None
    port = None

    sock_timeout = 3.0
    
    #message id
    KVP_IDCOUNTER = 0 #short

    """ Byte size of the various protocol messages fields """
    KVP_IDSIZE				= 2;
    KVP_LENSIZE				= 2;
    KVP_IPSIZE              = 4; #i.e. 0x255 0x255 0x255 0x0
    KVP_FUNCTIONSIZE		= 1;
    KVP_BLOCKSIZE			= 2;
    KVP_RESULTLENGTHSIZE    = 2;
    KVP_RESULTSIZE          = 1;

    KVP_FUNCTION_READ		= 0;
    KVP_FUNCTION_READARRAY	= 2;

    KVP_FUNCTION_WRITE		= 1;
    KVP_FUNCTION_WRITEARRAY	= 3;

    KVP_FUNCTION_DISCOVER   = 4; #MESSAGE BODY: [1 byte FUNCTION]
                                 #REPLY MESSAGE BODY: [1 byte FUNCTION][IP ADDRESSES COUNT][4 bytes IP ADDRESS * IP ADDRESSES COUNT][RESULT LENGTH][RESULT]

    KVP_FUNCTION_SETROBOTIP = 5; #MESSAGE BODY: [1 byte FUNCTION][4 bytes IP]
                                 #REPLY MESSAGE BODY: [1 byte FUNCTION][RESULT LENGTH][RESULT]

    KVP_RESULTOK			= 1;
    KVP_RESULTFAIL			= 0;

    def __init__(self, _host, _port, _sockTimeout = 3.0):
        self.host = _host
        self.port = _port
        self.sock_timeout = _sockTimeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect()

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect( (self.host, self.port) )
            self.sock.settimeout( self.sock_timeout )
        except:
            traceback.print_exc()

    def packMessage(self, kvp_func, dataToSend):
        """ Returns the buffer ready to be sent by socket
        """
        self.KVP_IDCOUNTER = self.KVP_IDCOUNTER + 1
        if self.KVP_IDCOUNTER==0xffff:
            self.KVP_IDCOUNTER = 0

        _buffer = bytearray()
        _buffer.extend( struct.pack(">H", self.KVP_IDCOUNTER) ) #little endian, unsigned short (2 bytes)

        _dataLen = self.KVP_FUNCTIONSIZE + len(dataToSend)

        if _dataLen > 0xffff or _dataLen < (self.KVP_FUNCTIONSIZE):
            raise Exception()
        
        _buffer.extend( struct.pack(">H", _dataLen) ) #little endian, unsigned short (2 bytes)

        _buffer.extend( struct.pack("B", kvp_func) ) #unsigned char (1 byte)

        _buffer.extend(dataToSend)
        return _buffer

    def read_message(self, data_length):
        data = bytearray()
        while (not self.sock is None) and (len(data) < data_length):
            try:
                readable, writable, errors = select.select([self.sock,], [], [], 0) #last parameter is timeout, when 0 is non blocking
                if self.sock in readable:
                    _data = self.sock.recv(data_length-len(data))
                    if len(_data) < 1:
                        return data 
                    data += _data
            except:
                #se il socket era risultato leggibile ma la lettura fallisce, allora si e' disconnesso
                self.sock = None
                return None
        return data

    def readVar(self, varName):
        """ Returns the variable value if success otherwise None """

        if self.sock == None:
            self.connect()

        _dataToSend = bytearray()
        _dataToSend.extend( struct.pack(">H", len(varName)))
        _dataToSend.extend(varName.encode("utf-8"))
        _msg = self.packMessage(self.KVP_FUNCTION_READ, _dataToSend)

        try:
            if self.sock.send(_msg) == len(_msg):
            
                _reply = self.read_message(4) #msg_id + msg_size
                _msgID, _msgSize = struct.unpack(">HH", _reply)

                if (not _msgID == self.KVP_IDCOUNTER) or (_msgSize < (self.KVP_FUNCTIONSIZE + self.KVP_BLOCKSIZE*2)):
                    print("readVar - recv bad response length")
                else:
                    _reply = self.read_message(_msgSize)
                    
                    if not _reply[0] == self.KVP_FUNCTION_READ:
                        print("readVar - invalid packet, the returned function doesn't match") 
                    else:
                        _reply = _reply[1:] #removing the first byte that is the function

                        _varValueSize = struct.unpack(">H", _reply[0:2])[0]
                        _reply = _reply[2:] #removing the variable value size

                        _varValue = struct.unpack("%ss"%_varValueSize, _reply[0:_varValueSize])[0]
                        _reply = _reply[_varValueSize:] #removing variable value

                        #this is not useful, the result size is 1, but I leave this as is
                        _resultSize = struct.unpack(">H", _reply[0:2])[0]
                        _reply = _reply[2:] #removing the result size

                        result = _reply[0]

                        if result == self.KVP_RESULTOK:
                            return _varValue
                        else:
                            print("readVar - result not OK")

            self.sock.close()
        except:
            print("readVar - exception, varname: %s"%varName)
            traceback.print_exc()
        
        self.sock = None
        return None

    def readArray(self, varName):
        """ varName (str): the variable name with [] at the end. i.e. MYARRAY[]
            Returns the array of shorts (2 bytes) if success otherwise None """

        if self.sock == None:
            self.connect()

        _dataToSend = bytearray()
        _dataToSend.extend( struct.pack(">H", len(varName)))
        _dataToSend.extend(varName.encode("utf-8"))
        _msg = self.packMessage(self.KVP_FUNCTION_READARRAY, _dataToSend)

        if self.sock.send(_msg) == len(_msg):
            try:
                _reply = self.read_message(4) #msg_id + msg_size
                _msgID, _msgSize = struct.unpack(">HH", _reply)

                if (not _msgID == self.KVP_IDCOUNTER) or (_msgSize < (self.KVP_FUNCTIONSIZE + self.KVP_BLOCKSIZE*2)):
                    print("readArray - recv bad response length")
                else:
                    _reply = self.read_message(_msgSize)
                    
                    if not _reply[0] == self.KVP_FUNCTION_READARRAY:
                        print("readArray - invalid packet, the returned function doesn't match") 
                    else:
                        _reply = _reply[1:] #removing the first byte that is the function

                        _varValueSize = struct.unpack(">H", _reply[0:2])[0]
                        _reply = _reply[2:] #removing the array size in bytes

                        _varValues = struct.unpack(">" + "H"*int(_varValueSize/2),_reply[0:_varValueSize])
                        _reply = _reply[_varValueSize:] #removing variable value

                        #this is not useful, the result size is 1, but I leave this as is
                        _resultSize = struct.unpack(">H", _reply[0:2])[0]
                        _reply = _reply[2:] #removing the result size

                        result = _reply[0]

                        if result == self.KVP_RESULTOK:
                            return _varValues
                        else:
                            print("readArray - result not OK")
                
                self.sock.close()
            except:
                print("readArray - exception")
                traceback.print_exc()
                
        self.sock = None
        return None

    def writeVar(self, varName, varValue):
        """ Returns True if success """

        if self.sock == None:
            self.connect()

        if len(varName) > 0xffff or len(varValue) > 0xffff:
            print("writeVar - var name or value too long")

        _dataToSend = bytearray()
        _dataToSend.extend( struct.pack(">H", len(varName)))
        _dataToSend.extend(varName.encode("utf-8"))
        _dataToSend.extend( struct.pack(">H", len(varValue)))
        _dataToSend.extend(varValue.encode("utf-8"))
        _msg = self.packMessage(self.KVP_FUNCTION_WRITE, _dataToSend)
        
        try:
            if self.sock.send(_msg) == len(_msg):
            
                _reply = self.read_message(4) #msg_id + msg_size
                _msgID, _msgSize = struct.unpack(">HH", _reply)

                if (not _msgID == self.KVP_IDCOUNTER) or (_msgSize < (self.KVP_FUNCTIONSIZE + self.KVP_BLOCKSIZE*2)):
                    print("writeVar - recv bad response length")
                else:
                    _reply = self.read_message(_msgSize)
                    
                    if not _reply[0] == self.KVP_FUNCTION_WRITE:
                        print("writeVar - invalid packet, the returned function doesn't match") 
                    else:
                        _reply = _reply[1:] #removing the first byte that is the function

                        _varValueSize = struct.unpack(">H", _reply[0:2])[0]
                        _reply = _reply[2:] #removing the variable value size

                        _varValue = struct.unpack("%ss"%_varValueSize, _reply[0:_varValueSize])[0]
                        _reply = _reply[_varValueSize:] #removing variable value

                        #this is not useful, the result size is 1, but I leave this as is
                        _resultSize = struct.unpack(">H", _reply[0:2])[0]
                        _reply = _reply[2:] #removing the result size

                        result = _reply[0]

                        if result == self.KVP_RESULTOK:
                            return True
                        else:
                            print("writeVar - result not OK")
            self.sock.close()
        except:
            print("writeVar - exception, varname: %s"%varName)
            traceback.print_exc()
                
        self.sock = None
        return False

    def writeArray(self, varName, varValues):
        """ varName (str): the variable name with [] at the end. i.e. MYARRAY[]
            varValues (list of shorts (2bytes)): the array values
            Returns True if success 
        
        """

        if self.sock == None:
            self.connect()

        if len(varName) > 0xffff or len(varValues) > 0xffff:
            print("writeVar - var name or value too long")

        _dataToSend = bytearray()
        _dataToSend.extend( struct.pack(">H", len(varName)))
        _dataToSend.extend(varName.encode("utf-8"))
        _dataToSend.extend( struct.pack(">H", len(varValues)*2))
        _dataToSend.extend(struct.pack(">%sH"%len(varValues),*varValues))
        _msg = self.packMessage(self.KVP_FUNCTION_WRITEARRAY, _dataToSend)
        
        if self.sock.send(_msg) == len(_msg):
            try:
                _reply = self.read_message(4) #msg_id + msg_size
                _msgID, _msgSize = struct.unpack(">HH", _reply)

                if (not _msgID == self.KVP_IDCOUNTER) or (_msgSize < (self.KVP_FUNCTIONSIZE + self.KVP_BLOCKSIZE*2)):
                    print("writeArray - recv bad response length")
                else:
                    _reply = self.read_message(_msgSize)
                    
                    if not _reply[0] == self.KVP_FUNCTION_WRITEARRAY:
                        print("writeArray - invalid packet, the returned function doesn't match") 
                    else:
                        _reply = _reply[1:] #removing the first byte that is the function

                        _varNameSize = struct.unpack(">H", _reply[0:2])[0]
                        _reply = _reply[2:] #removing the variable name size

                        _varValue = struct.unpack("%ds"%_varNameSize, _reply[0:_varNameSize])[0]
                        _reply = _reply[_varNameSize:] #removing variable value

                        #this is not useful, the result size is 1, but I leave this as is
                        _resultSize = struct.unpack(">H", _reply[0:2])[0]
                        _reply = _reply[2:] #removing the result size

                        result = _reply[0]

                        if result == self.KVP_RESULTOK:
                            return True
                        else:
                            print("writeArray - result not OK")
                self.sock.close()
            except:
                print("writeArray - exception")
                traceback.print_exc()
                
        self.sock = None
        return False

    def parseStructure(self, value):
        """ Given a variable value of type struct, 
            this function returns a dictionary three of the parsed value

            value (str): the kuka string representation of a struct 

            Returns a dictionary
        """
        resultDict = {}
        value = value[value.index(':'):]
        value = value.replace('{','').replace(' ','').replace('}','')
        fields = value.split(',')
        for v in fields:
            v = v.strip()
            fieldName = v[:v.index(' ')]
            fieldValue = v[v.index(' ')+1:]
            resultDict[fieldName] = fieldValue

            if fieldValue.startswith('{'):
                resultDict[fieldName] = self.parseStructure(fieldValue)
        return resultDict

    def packStructure(self, structTypeName, valuesDict):
        ret = '{%s:'%structTypeName
        for fieldName, fieldValue in valuesDict.items():
            if type(fieldValue) == dict:
                fieldValue = self.parseStructure(fieldName, fieldValue)
            ret = ret + " " + fieldName + " " + str(fieldValue) + ","

        return ret

    def discoverRobots(self):
        """ Returns the IPs of the available robots  """
        ipList = []

        if self.sock == None:
            self.connect()

        #MESSAGE BODY: [1 byte FUNCTION]
        _dataToSend = bytearray()
        _msg = self.packMessage(self.KVP_FUNCTION_DISCOVER, _dataToSend)

        try:
            if self.sock.send(_msg) == len(_msg):
                #REPLY MESSAGE BODY: [1 byte FUNCTION][2 bytes IP ADDRESSES COUNT][4 bytes IP ADDRESS * IP ADDRESSES COUNT][RESULT LENGTH][RESULT]
                _reply = self.read_message(4) #msg_id + msg_size
                _msgID, _msgSize = struct.unpack(">HH", _reply)

                if (not _msgID == self.KVP_IDCOUNTER) or (_msgSize < (self.KVP_FUNCTIONSIZE + self.KVP_BLOCKSIZE*2 + 1)):
                    print("readVar - recv bad response length")
                else:
                    _reply = self.read_message(_msgSize)
                    
                    if not _reply[0] == self.KVP_FUNCTION_DISCOVER:
                        print("readVar - invalid packet, the returned function doesn't match") 
                    else:
                        _reply = _reply[1:] #removing the first byte that is the function

                        _ipAddressCount = struct.unpack(">H", _reply[0:2])[0]
                        _reply = _reply[2:] #removing the variable value size

                        for ip_index in range(0, _ipAddressCount):
                            ip = _reply[0:4]
                            ipList.append(ip)
                            _reply = _reply[4:] #removing variable value

                        #this is not useful, the result size is 1, but I leave this as is
                        _resultSize = struct.unpack(">H", _reply[0:2])[0]
                        _reply = _reply[2:] #removing the result size

                        result = _reply[0]

                        if result == self.KVP_RESULTOK:
                            return ipList
                        else:
                            print("readVar - result not OK")

            self.sock.close()
        except:
            traceback.print_exc()
        
        self.sock = None
        return []

    def setRobotIP(self, ip):
        """ Sets the ip of the server robot 
            Args:
                ip (list) = list of 4 ip bytes
        """
        #MESSAGE BODY: [1 byte FUNCTION][4 bytes IP]

        if self.sock == None:
            self.connect()

        _dataToSend = bytearray(ip)
        _msg = self.packMessage(self.KVP_FUNCTION_SETROBOTIP, _dataToSend)

        try:
            if self.sock.send(_msg) == len(_msg):
                #REPLY MESSAGE BODY: [1 byte FUNCTION][RESULT LENGTH][RESULT]
                _reply = self.read_message(4) #msg_id + msg_size
                _msgID, _msgSize = struct.unpack(">HH", _reply)

                if (not _msgID == self.KVP_IDCOUNTER) or (_msgSize < (self.KVP_FUNCTIONSIZE + self.KVP_BLOCKSIZE + 1)):
                    print("readVar - recv bad response length")
                else:
                    _reply = self.read_message(_msgSize)
                    
                    if not _reply[0] == self.KVP_FUNCTION_SETROBOTIP:
                        print("readVar - invalid packet, the returned function doesn't match") 
                    else:
                        _reply = _reply[1:] #removing the first byte that is the function

                        #this is not useful, the result size is 1, but I leave this as is
                        _resultSize = struct.unpack(">H", _reply[0:2])[0]
                        _reply = _reply[2:] #removing the result size

                        result = _reply[0]

                        if result == self.KVP_RESULTOK:
                            return True
                        else:
                            print("readVar - result not OK")

            self.sock.close()
        except:
            traceback.print_exc()
        
        self.sock = None
        return False



libPath = '/R1/sickodvaluelib/'
kukavarproxyIP = '127.0.0.1'
robotPort = 7000

sockPartner = None

def parseValue(stringa):
    try:
        return float(stringa)
    except:
        if stringa.lower() == 'true':
            return True
        if stringa.lower() == 'false':
            return False
        return stringa

def toPythonDict(stringa):
    i = 0
    resultDict = {}
    field = ""
    jumpSubStruct = 0
    for c in stringa:
        i += 1
        if jumpSubStruct > 0: #per scartare le sottostrutture
            if c=='{':
                jumpSubStruct += 1
                continue
            if c=='}':
                jumpSubStruct -= 1
                continue

        if c=='{':
            jumpSubStruct += 1
            field = field.strip()
            fieldName = field
            fieldValue = toPythonDict(stringa[i:])

            resultDict[fieldName] = fieldValue
            field = ""
            continue

        if c==':': #per scartare il nome struttura
            field = ""
            continue

        elif c==',': #per separare i campi
            field = field.strip()

            if len(field)<1: #dopo il parse di una struttura
                continue

            if len(field.split(' '))<2: #campo senza valore
                field = ""
                continue
            fieldName, fieldValue = field[:field.index(' ')], field[field.index(' ')+1:]
            
            resultDict[fieldName] = parseValue(fieldValue)
            field = ""
            continue

        elif c=='}': #per separare i campi
            field = field.strip()

            if len(field)<1: #dopo il parse di una struttura
                break

            if len(field.split(' '))<2: #campo senza valore
                field = ""
                break
            fieldName, fieldValue = field[:field.index(' ')], field[field.index(' ')+1:]
            
            resultDict[fieldName] = parseValue(fieldValue)
            field = ""
            break
        
        else:
            field += c

    return resultDict    


if __name__ == '__main__':
    kvp = KukaVarProxyClient(kukavarproxyIP, robotPort)
    IPs = []
    while len(IPs) < 1:
        print("discovering robots...")
        IPs = kvp.discoverRobots()

    print("Found IPs:")
    for ip in IPs:
        print(f"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}")

    kvp.setRobotIP(IPs[0])

    stringa = kvp.readVar("$OV_PRO").decode()
    print(stringa)
    stringa = stringa[stringa.index('{')+1: stringa.rindex('}') ]
    print("DEBUG: ", toPythonDict(stringa))
