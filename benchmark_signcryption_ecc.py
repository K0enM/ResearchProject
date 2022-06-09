from signcryption_ecc import SigncryptionEcc
from charm.toolbox.eccurve import prime256v1
import os
import pickle

sc = SigncryptionEcc(curve=prime256v1, debug=False)
group = sc.group
trials = 20000

assert group.InitBenchmark()
group.StartBenchmark(["Mul", "Div", "Exp", "RealTime", "CpuTime", "Add", "Sub"])
for i in range(trials):
    pk_a, sk_a = sc.keygen()
    pk_b, sk_b = sc.keygen(g=pk_a['g'])
    msg = os.urandom(28)
    original_len = len(msg)

    ciphertext = sc.signcrypt(pk_b, sk_a, msg)

    message_len = len(pickle.dumps(str(ciphertext)))

    valid, unsigncrypt = sc.unsigncrypt(pk_a, sk_b, ciphertext)
    assert unsigncrypt == msg
    assert valid
    print(f'Message overhead iteration {i} is: {((message_len - original_len) / original_len) * 100}%')
group.EndBenchmark()
msmtDict = group.GetGeneralBenchmarks()
print(msmtDict)