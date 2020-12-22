import base64
import string
import random
import binascii
import struct
import sys
import pprint

WIN_DEFEND_RUNNING = 1
WIN_DEFEND_STOPPED = 2
WIN_DEFEND_ATP_RUNNING = 4
WIN_DEFEND_ATP_STOPPED = 8
MS_DEFENDER_ID_RUNNING = 16
MS_DEFENDER_ID_STOPPED = 32
CARBON_BLACK_RUNNING=64
CARBON_BLACK_STOPPED=128
CROWDSTRIKE_RUNNING=256
CROWDSTRIKE_STOPPED=512
FIREEYE_RUNNING=1024
FIREEYE_STOPPED=2048
ESET_RUNNING=4096
ESET_STOPPED=8192
FSECURE_RUNNING=16384
FSECURE_STOPPED=32768

def get_flags(a):
    ret = []
    if a & WIN_DEFEND_RUNNING:
        ret.append("Windows Defender Running")
    if a & WIN_DEFEND_STOPPED:
        ret.append("WINDOWS DEFENDER STOPPED")
    if a & WIN_DEFEND_ATP_RUNNING:
        ret.append("WINDOWS DEFENDER ATP RUNNING")
    if a & WIN_DEFEND_ATP_STOPPED:
        ret.append("WINDOWS DEFENDER ATP STOPPED")
    if a & MS_DEFENDER_ID_RUNNING:
        ret.append("MS DEFENDER ID RUNNING")
    if a & MS_DEFENDER_ID_STOPPED:
        ret.append("MS DEFENDER ID STOPPED")
    if a & CARBON_BLACK_RUNNING:
        ret.append("CARBONBLACK RUNNING")
    if a & CARBON_BLACK_STOPPED:
        ret.append("CarbonBlack STOPPED")
    if a & CROWDSTRIKE_RUNNING:
        ret.append("CROWDSTRIKE RUNNING")
    if a & CROWDSTRIKE_STOPPED:
        ret.append("CROWDSTRIKE STOPPED")
    if a & FIREEYE_RUNNING:
        ret.append("FIREEYE RUNNING")
    if a & FIREEYE_STOPPED:
        ret.append("FIREYE STOPPED")
    if a & ESET_RUNNING:
        ret.append("ESET RUNNING")
    if a & ESET_STOPPED:
        ret.append("ESET STOPPED")
    if a & FSECURE_RUNNING:
        ret.append("FSECURE RUNNING")
    if a & FSECURE_STOPPED:
        ret.append("FSECURE STOPPED")
    return ret


def custom_b32decode(s):
    std_base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    my_base32chars = "ph2eifo3n5utg1j8d94qrvbmk0sal76c"
    temp = s.translate(string.maketrans(my_base32chars, std_base32chars))
    return base64.b32decode(temp)


#From @RedDrip7  - Fix datalen calculation by @sysopfb
def Base32Decode(string):
	text = "ph2eifo3n5utg1j8d94qrvbmk0sal76c"
	restring = ""
	datalen = len(string) * 5 / 8
	num = 0
	ib = 0;
	if len(string) < 3:
		restring = chr(text.find(string[0]) | text.find(string[1]) << 5 & 255)
		return restring
	
	k = text.find(string[0]) | (text.find(string[1]) << 5)
	j = 10
	index = 2
	for i in range(datalen):
		restring += chr(k & 255)
		k = k >> 8
		j -= 8
		while( j < 8 and index < len(string)):
			k |= (text.find(string[index]) << j)
			index += 1
			j += 5

	return restring


#From @RedDrip7  
def Decode(string):
	text = "rq3gsalt6u1iyfzop572d49bnx8cvmkewhj"
	text2 = "0_-."
	retstring = ""
	flag = False
	for i in range(len(string)):
		ch = string[i]
		tx_index = -1
		tx2_index = -1
		if flag:
			t1i = text.find(ch)
			x = t1i - ((random.randint(0,8) % (len(text) / len(text2))) * len(text2))
			retstring = retstring+text2[x % len(text2)]
			flag = False
			continue
		if ch in text2:
			tx2_index = text2.find(ch)
			flag = True
			pass
		else:
			tx_index = text.find(ch)
			oindex = tx_index - 4
			retstring = retstring+text[oindex % len(text)]

		pass
	return retstring



def get_subdomain(s):
    ret = None
    if '.appsync-api.' in s:
        ret = s.split('.appsync-api.')[0]
    return ret

full_data = {}

def decode(s):
    d = get_subdomain(s)
    if d == None or len(d) < 15:
        return None
    else:
        user_id = bytearray(Base32Decode(d[:15]))
        key = user_id[0]
        user_id = user_id[1:]
        for i in range(len(user_id)):
            user_id[i] ^= key
        part = ord(d[0]) % 36 - "0123456789abcdefghijklmnopqrstuvwxyz".index(d[15])
        if d[16:18] == '00':
            decoded = Base32Decode(d[18:])
        else:
            decoded = Decode(d[16:])
        if part in [0,1,2]:
            print("User ID:" + binascii.hexlify(user_id))
            print("Domain Part Number: "+ str(part))
            print("Domain: " + decoded)
            if binascii.hexlify(user_id) not in full_data.keys():
                full_data[binascii.hexlify(user_id)] = {part: decoded}
            else:
                full_data[binascii.hexlify(user_id)][part]=decoded
        else:
            #Data
            decoded = bytearray(Base32Decode(d))
            for i in range(1,len(decoded)):
                decoded[i] ^= decoded[0]
            user_id = decoded[1:9]
            key = decoded[10:12]
            for i in range(len(user_id)):
                user_id[i] ^= key[(i+1)%len(key)]

            blob = decoded[9:]
            print("DEBUG: "+binascii.hexlify(blob))
            if len(blob) < 3:
                return
            data_len = (blob[0] & 0xf0) >> 4
            timestamp = struct.unpack_from('>I', '\x00'+blob[:3])[0] & 0xfffff
            data = blob[3:]
            print("User ID:" + binascii.hexlify(user_id))
            if binascii.hexlify(user_id) not in full_data.keys():
                full_data[binascii.hexlify(user_id)] = {}
            print("TimeStamp:" + hex(timestamp))
            if data_len < 2:
                print("PING")
            else:
                print("Data Length:" + str(data_len))
                print("Data:" + binascii.hexlify(data))
                flags = get_flags(struct.unpack_from('>H',data)[0])
                print(flags)
                full_data[binascii.hexlify(user_id)]['AV'] = flags
    return decoded


test = 'lt5ai41qh5d53qoti3mkmc0.appsync-api.us-west-2.avsvmcloud.com'

test2 = get_subdomain(test)

temp = Base32Decode(test2)
print(binascii.hexlify(temp))
decode(test)

data = open(sys.argv[1], 'rb').read()
for line in data.split('\n'):
    try:
        decode(line)
    except:
        continue

pprint.pprint(full_data)
