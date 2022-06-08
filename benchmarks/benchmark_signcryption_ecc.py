from signcryption_ecc import SigncryptionEcc
from charm.toolbox.eccurve import prime192v1
import os

sc = SigncryptionEcc(curve=prime192v1, debug=False)
group = sc.group
trials = 20

assert group.InitBenchmark()
group.StartBenchmark(["Mul", "Div", "Exp", "RealTime", "CpuTime", "Add", "Sub"])
for i in range(trials):
    pk_a, sk_a = sc.keygen()
    pk_b, sk_b = sc.keygen(g=pk_a['g'])
    msg = b"\x00" + os.urandom(1024) + b"\x00"

    ciphertext = sc.signcrypt(pk_b, sk_a, msg)
    valid, unsigncrypt = sc.unsigncrypt(pk_a, sk_b, ciphertext)
    assert unsigncrypt == msg
    assert valid
group.EndBenchmark()
msmtDict = group.GetGeneralBenchmarks()
print(msmtDict)