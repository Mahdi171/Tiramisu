from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import Input, Output
from charm.core.engine.util import objectToBytes

pp_t = { 'g':G1, 'h':G2, 'e_gh': GT }
pk_t = { 'pk1':G1, 'pk2':G2}
sk_t = { 'sk':ZR }
Pi_t = { 'Pi1': G1, 'Pi2': G2 }
ct_t = {'c1': GT, 'c2': GT}
ctRO_t = {'c1': G1, 'c2': ZR}
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
    @Output(str)
    def KV(self, pp, pk, Pi, n):
        for i in range(n):
            if i==0:
                if pair(Pi[i]["Pi1"],pp['h']) == pair(pp['g'], pk[i]["pk2"]) and \
                    pair(pp['g'], Pi[i]["Pi2"]) == pair(pk[i]["pk1"],pp['h']) and \
                        pair(pp['g'], Pi[i]["Pi2"]) == pair(Pi[i]["Pi1"], pp['h']):
                        return "The key is consistent"
                else:
                    return "The key is not consistent"
            else:
                if pair((pk[int(i)-1]["pk1"] * Pi[i]["Pi1"]),pp['h']) == pair(pp['g'], pk[i]["pk2"]) and \
                    pair(pp['g'], (pk[int(i)-1]["pk2"] * Pi[i]["Pi2"])) == pair(pk[i]["pk1"],pp['h']) and \
                        pair(pp['g'], Pi[i]["Pi2"]) == pair(Pi[i]["Pi1"], pp['h']):
                        return "The key is consistent"
                else:
                    return "The key is not consistent"
    
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
        c1 = mes + group.hash(pk['pk1']**r)
        c2 = pp['g'] ** r
        return {'c1': c1, 'c2': c2}

    @Input(pp_t, dict, ct_t)
    @Output(GT)
    def Dec(self, pp, sk, ct):
        sec=0
        for i in sk:
            sec += sk[i]['sk']
        return ct['c1']/(ct['c2']**sec)



def start_bench(group):
    group.InitBenchmark()
    group.StartBenchmark(["RealTime", "CpuTime"])

def end_bench(group, operation, n):
    group.EndBenchmark()
    benchmarks = group.GetGeneralBenchmarks()
    cpu_time = benchmarks['CpuTime']
    real_time = benchmarks['RealTime']
    return "%s,%f,%f" % (operation, cpu_time, real_time)



# Test
def run_round_trip(n):
    groupObj = PairingGroup('BN254')
    Tir = Tiramisu(groupObj)
    pk={}; Pi={}; sk={}

    # Setup
    start_bench(groupObj)
    (pp)= Tir.Setup()
    setup_time = end_bench(groupObj, "Setup", n)
    public_parameters_size = len(objectToBytes(pp, groupObj))

    # Key Gen
    start_bench(groupObj)
    (pk[0],Pi[0],sk[0])=Tir.KG(pp)
    Key_Gen_time = end_bench(groupObj, "Key Gen", n)
    public_key_size = len(objectToBytes(pk[0], groupObj))
    # Key Update
    start_bench(groupObj)
    for i in range(1,n+1):
        (pk[i],Pi[i],sk[i])=Tir.KU(pp, pk[i-1])
    Key_update_time = end_bench(groupObj, "Key_update", n)
    public_updated_key_size = len(objectToBytes(pk, groupObj))


    # Key verification
    start_bench(groupObj)
    pk_final=pk[n]
    (out) = Tir.KV(pp,pk,Pi,n)
    Key_verification_time = end_bench(groupObj, "Key_Verification", n)


    # Encryption
    start_bench(groupObj)
    rand_msg = groupObj.random(GT)
    (ct) = Tir.Enc(pp,pk_final,rand_msg)
    encryption_time = end_bench(groupObj, "Encryption", n)
    Ciphertext_size = len(objectToBytes(ct, groupObj))


    # Decryption
    start_bench(groupObj)
    rec_msg = Tir.Dec(pp, sk, ct)
    decryption_time = end_bench(groupObj, "Key_update", n)

    
    return {'\nsetup_time': setup_time ,
            '\n Keygen_time': Key_Gen_time,
            '\nKey_update_time': Key_update_time,
            '\nVerification_times': Key_verification_time,
            '\nencrypt_exec_time': encryption_time,
            '\ndecrypt_exec_time': decryption_time
            }


for n in range(1, 2):
    result = run_round_trip(10000)
    print("function,CpuTime,RealTime")
    [print(v) for v in result.values()]

#print("\nPublic paramters size", public_parameters_size)
#print("\nPublic key size", public_key_size)
#print("\nupdated key size", public_updated_key_size)
#print("\n ciphertext size", ciphertext_size)