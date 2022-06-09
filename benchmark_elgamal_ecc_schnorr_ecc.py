import os
import pickle
from schnorr_ecc import SchnorrEcc

from charm.schemes.pkenc.pkenc_elgamal85 import ElGamal
from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.eccurve import prime256v1
from charm.toolbox.conversion import Conversion

trials = 20
group = ECGroup(prime256v1)
elgamal = ElGamal(group)
schnorr = SchnorrEcc(prime256v1)

assert group.InitBenchmark()
group.StartBenchmark(["Mul", "Div", "Exp", "RealTime", "CpuTime", "Add", "Sub"])
for i in range(trials):
    pk_sig, sk_sig = schnorr.keygen()
    pk_enc, sk_enc = elgamal.keygen(secparam=2048)

    msg = os.urandom(28)
    original_len = len(msg)

    S = schnorr.sign(pk=pk_sig, sk=sk_sig, message=msg)

    signature_bytes = Conversion.IP2OS(int(S['s']))
    signature_bytes += Conversion.IP2OS(int(S['r']))

    ciphertext = elgamal.encrypt(pk_enc, msg)
    message_len = len(pickle.dumps(str(ciphertext)))
    unencrypted = elgamal.decrypt(pk_enc, sk_enc, ciphertext)

    assert msg == unencrypted
    assert schnorr.verify(pk_sig, msg, S)
    print(f'Message overhead iteration {i} is: {((message_len - original_len) / original_len) * 100}%')
group.EndBenchmark()
msmtDict = group.GetGeneralBenchmarks()
print(msmtDict)
