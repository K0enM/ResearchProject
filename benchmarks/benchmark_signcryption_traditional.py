from signcryption_traditional import Signcryption
import os
import pickle

sc = Signcryption(debug=False, bits=2048)
group = sc.group
trials = 20

assert group.InitBenchmark()
group.StartBenchmark(["Mul", "Div", "Exp", "RealTime", "CpuTime", "Add", "Sub"])
for i in range(trials):
    pk_a, sk_a = sc.keygen()
    pk_b, sk_b = sc.keygen(g=pk_a['g'])
    msg = os.urandom(16)
    original_len = len(msg)

    ciphertext = sc.signcrypt(pk_b, sk_a, msg)
    ciphertext_dict = {'c': ciphertext['c'], 'r': int(ciphertext['r']), 's': int(ciphertext['s'])}
    message_len = len(pickle.dumps(ciphertext_dict))

    valid, unsigncrypt = sc.unsigncrypt(pk_a, sk_b, ciphertext)
    assert unsigncrypt == msg
    assert valid
    print(f'Message overhead iteration {i} is: {((message_len - original_len) / original_len) * 100}%')
group.EndBenchmark()
msmtDict = group.GetGeneralBenchmarks()
print(msmtDict)
