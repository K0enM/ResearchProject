import os
import pickle
from charm.schemes.pkenc.pkenc_elgamal85 import ElGamal
from charm.toolbox.integergroup import IntegerGroupQ
from charm.schemes.pksig.pksig_dsa import DSA
from charm.toolbox.conversion import Conversion
trials = 20
group = IntegerGroupQ()
elgamal = ElGamal(group)
dsa = DSA()

assert group.InitBenchmark()
group.StartBenchmark(["Mul", "Div", "Exp", "RealTime", "CpuTime", "Add", "Sub"])
for i in range(trials):
    pk_sig, sk_sig = dsa.keygen(bits=128)
    pk_enc, sk_enc = elgamal.keygen(secparam=2048)

    msg = os.urandom(20)
    original_len = len(msg)

    S = dsa.sign(pk=pk_sig, x=sk_sig, M=msg)
    signature_bytes = Conversion.IP2OS(S['r'])
    ciphertext = elgamal.encrypt(pk_enc, msg)
    ciphertext_dict = {'c1': int(ciphertext['c1']), 'c2': int(ciphertext['c2'])}

    message_len = len(pickle.dumps(ciphertext_dict))
    unencrypted = elgamal.decrypt(pk_enc, sk_enc, ciphertext)

    print(Conversion.IP2OS(S['r']))
    print(unencrypted)

    assert msg == unencrypted
    assert dsa.verify(pk_sig, S, unencrypted)
    print(f'Message overhead iteration {i} is: {((message_len - original_len) / original_len) * 100}%')
group.EndBenchmark()
msmtDict = group.GetGeneralBenchmarks()
print(msmtDict)
