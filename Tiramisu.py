from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import Input, Output
from charm.core.engine.util import objectToBytes
from openpyxl import load_workbook
from openpyxl import Workbook
from hashlib import sha256 as sha256
import os


def zero_bytes(n):
    return n * b"\x00"

def to_bytes(l): # where l is a list or bytearray or bytes
    return bytes(bytearray(l))

def bytes_to_int(bytes):
    return sum([bi << ((len(bytes) - 1 - i)*8) for i, bi in enumerate(to_bytes(bytes))])

def bytes_to_state(bytes):
    return [bytes_to_int(bytes[8*w:8*(w+1)]) for w in range(5)]

def int_to_bytes(integer, nbytes):
    return to_bytes([(integer >> ((nbytes - 1 - i) * 8)) % 256 for i in range(nbytes)])

def rotr(val, r):
    return ((val >> r) ^ (val << (64-r))) % (1 << 64)

def bytes_to_hex(b):
    return b.hex()
    #return "".join(x.encode('hex') for x in b)




pp_t = { 'g':G1, 'h':G2, 'e_gh': GT }
pk_t = { 'pk1':G1, 'pk2':G2}
sk_t = { 'sk':ZR }
Pi_t = { 'Pi1': G1, 'Pi2': G2 }
ct_t = {'c1': GT, 'c2': GT}
ctRO_t = {'c1': int, 'c2': G1}
class Tiramisu():
         
    def __init__(self, groupObj):
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj
    
    @Output(pp_t)    
    def Setup(self):
        g, h = group.random(G1), group.random(G2)
        g.initPP(); h.initPP()
        e_gh = pair(g,h)
        return { 'g': g, 'h': h, 'e_gh': e_gh }

    @Input(pp_t)
    @Output(pk_t, Pi_t, sk_t)    
    def KG(self,pp):
        seck = group.random(ZR)
        pk1 = pp['g'] ** seck; pk2= pp['h'] ** seck
        pk = { 'pk1': pk1, 'pk2': pk2 }
        sk = { 'sk': seck }
        Pi = { 'Pi1': pk1, 'Pi2': pk2 }
        return (pk, Pi, sk)

    @Input(pp_t, pk_t)
    @Output(pk_t, Pi_t, sk_t)
    def KU(self, pp, pk):
        seck = group.random(ZR)
        pk1 = pk['pk1'] * (pp['g'] ** seck); pk2 = pk['pk2'] * (pp['h'] ** seck)
        Pi1 = pp['g'] ** seck; Pi2 = pp['h'] ** seck
        pk = {'pk1': pk1, 'pk2': pk2}
        Pi = {'Pi1': Pi1, 'Pi2': Pi2}
        sk = {'sk': seck}
        return (pk, Pi, sk)

    @Input(pp_t, dict, dict, int)
    @Output(int)
    def KV(self, pp, pk, Pi, n):
        for i in range(n):
            if i==0:
                pair(Pi[i]["Pi1"],pp['h']) == pair(pp['g'], pk[i]["pk2"])
                pair(pp['g'], Pi[i]["Pi2"]) == pair(pk[i]["pk1"],pp['h'])
                pair(pp['g'], Pi[i]["Pi2"]) == pair(Pi[i]["Pi1"], pp['h'])
            else:
                pair((pk[int(i)-1]["pk1"] * Pi[i]["Pi1"]),pp['h']) == pair(pp['g'], pk[i]["pk2"])
                pair(pp['g'], (pk[int(i)-1]["pk2"] * Pi[i]["Pi2"])) == pair(pk[i]["pk1"],pp['h'])
                pair(pp['g'], Pi[i]["Pi2"]) == pair(Pi[i]["Pi1"], pp['h'])
        return i
    
    @Input(pp_t, pk_t, GT)
    @Output(ct_t)
    def Enc(self, pp, pk_final, mes):
        r = group.random(ZR)
        c1 = mes * pair(pk_final['pk1'],pp['h'])**r
        c2 = pp['e_gh'] ** r
        return {'c1': c1, 'c2': c2}

    
    @Input(pp_t, pk_t, ZR)
    @Output(ctRO_t)
    def EncRO(self, pp, pk_final, mes):
        r = group.random(ZR)
        pubkey1 = pk_final['pk1'] ** r
        pubkey2 = objectToBytes(pubkey1, group)
        mes1 = objectToBytes(mes, group)
        mes2 = bytes_to_int(mes1)
        hash0 = group.hash(pubkey2, ZR)
        hash1 = objectToBytes(hash0, group)
        hash2 = bytes_to_int(hash1)
        c1 = mes2 ^ hash2
        c2 = pp['g'] ** r
        return {'c1': c1, 'c2': c2}

    @Input(pp_t, dict, ct_t)
    @Output(GT)
    def Dec(self, pp, sk, ct):
        sec=0
        for i in sk:
            sec += sk[i]['sk']
        return ct['c1']/(ct['c2']**sec)

    @Input(pp_t, dict, ctRO_t)
    @Output(int)
    def DecRO(self, pp, sk, ctRO):
        sec=0
        for i in sk:
            sec += sk[i]['sk']
        cipher1 = ctRO['c2'] ** sec
        cipher2 = objectToBytes(cipher1, group)
        cipher3 = group.hash(cipher2, ZR)
        cipher4 = objectToBytes(cipher3, group)
        cipher5 = bytes_to_int(cipher4)
        return ctRO['c1'] ^ cipher5


def start_bench(group):
    group.InitBenchmark()
    group.StartBenchmark(["RealTime"])

def end_bench(group):
    group.EndBenchmark()
    benchmarks = group.GetGeneralBenchmarks()
    real_time = benchmarks['RealTime']
    return real_time

groupObj = PairingGroup('BN254')
Tir = Tiramisu(groupObj)

# Test
def run_round_trip(n):

    pk={}; Pi={}; sk={}
    result=[n]
    # Setup
    start_bench(groupObj)
    (pp)= Tir.Setup()
    setup_time = end_bench(groupObj)
    result.append(setup_time)
    public_parameters_size = len(objectToBytes(pp, groupObj))
    result.append(public_parameters_size)
    # Key Gen
    start_bench(groupObj)
    (pk[0],Pi[0],sk[0])=Tir.KG(pp)
    Key_Gen_time = end_bench(groupObj)
    result.append(Key_Gen_time)
    public_key_size = len(objectToBytes(pk[0], groupObj))
    result.append(public_key_size)
    # Key Update

    start_bench(groupObj)
    for i in range(1,n+1):
        (pk[i],Pi[i],sk[i])=Tir.KU(pp, pk[i-1])
    Key_update_time = end_bench(groupObj)
    result.append(Key_update_time)
    public_updated_key_size = (len(objectToBytes(pk, groupObj))+len(objectToBytes(Pi, groupObj)))/8
    result.append(public_updated_key_size)

    # Key verification
    Key_verification_time=0
    
    for i in range(3):
        start_bench(groupObj)
        j=Tir.KV(pp,pk,Pi,n)
        Key_verification_time += end_bench(groupObj)
    Key_verification_time=Key_verification_time/3
    result.append(Key_verification_time)

    # Encryption
    pk_final=pk[n]
    start_bench(groupObj)
    rand_msg = groupObj.random(GT)
    (ct) = Tir.Enc(pp,pk_final,rand_msg)
    encryption_time = end_bench(groupObj)
    encryption_time = encryption_time * 1000
    result.append(encryption_time)
    Ciphertext_size = len(objectToBytes(ct, groupObj))
    result.append(Ciphertext_size)
    msg = groupObj.random(ZR)

    start_bench(groupObj)
    (ctRO)=Tir.EncRO(pp,pk_final,msg)
    encryption_RO_time = end_bench(groupObj)
    encryption_RO_time = encryption_RO_time * 1000
    result.append(encryption_RO_time)
    Ciphertext_RO_size = len(objectToBytes(ctRO, groupObj))
    result.append(Ciphertext_RO_size)

    # Decryption
    start_bench(groupObj)
    rec_msg = Tir.Dec(pp, sk, ct)
    decryption_time = end_bench(groupObj)
    decryption_time = decryption_time * 1000
    result.append(decryption_time)

    msg = objectToBytes(msg, groupObj)
    msg = bytes_to_int(msg)
    start_bench(groupObj)
    rec = Tir.DecRO(pp, sk, ctRO)
    decryption_RO_time = end_bench(groupObj)
    decryption_RO_time = decryption_RO_time * 1000
    result.append(decryption_RO_time)
    return result


book=Workbook()
data=book.active
title=["n","setup_time","public_parameters_size", "Key_Gen_time","public_key_size","Key_update_time","update_key_size", "key_verification_time", "encryption_time" ,"Ciphertext_size","encryption_RO_time","Ciphertext_RO_size","Decryption_time", "decryption_RO_time"]
data.append(title)

for n in range(1, 2):
    data.append(run_round_trip(n))
    print(n)

book.save("TirResulttest.xlsx")


