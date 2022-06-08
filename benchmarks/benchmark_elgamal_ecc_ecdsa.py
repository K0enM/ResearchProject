import os
import pickle

from charm.schemes.pkenc.pkenc_elgamal85 import ElGamal
from charm.schemes.pksig.pksig_ecdsa import ECDSA
from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.eccurve import prime192v1
from charm.toolbox.conversion import Conversion

trials = 20
group = ECGroup(prime192v1)
elgamal = ElGamal(group)
ecdsa = ECDSA(group)

assert group.InitBenchmark()
group.StartBenchmark(["Mul", "Div", "Exp", "RealTime", "CpuTime", "Add", "Sub"])
for i in range(trials):
    pk_sig, sk_sig = ecdsa.keygen(bits=128)
    pk_enc, sk_enc = elgamal.keygen(secparam=2048)

    msg = os.urandom(16)
    original_len = len(msg)

    S = ecdsa.sign(pk=pk_sig, x=sk_sig, M=msg)

    signature_bytes = Conversion.IP2OS(int(S['s']))
    signature_bytes += Conversion.IP2OS(int(S['r']))

    ciphertext = elgamal.encrypt(pk_enc, msg)
    message_len = len(pickle.dumps(str(ciphertext)))
    unencrypted = elgamal.decrypt(pk_enc, sk_enc, ciphertext)

    assert msg == unencrypted
    assert ecdsa.verify(pk_sig, S, unencrypted)
    print(f'Message overhead iteration {i} is: {((message_len - original_len) / original_len) * 100}%')
group.EndBenchmark()
msmtDict = group.GetGeneralBenchmarks()
print(msmtDict)
