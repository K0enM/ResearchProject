from signcryption_traditional import Signcryption

sc = Signcryption(debug=False, bits=2048)
group = sc.group
trials = 100

assert group.InitBenchmark()
group.StartBenchmark(["Mul", "Div", "Exp", "RealTime", "CpuTime", "Add", "Sub"])
for i in range(trials):
    pk_a, sk_a = sc.keygen()
    pk_b, sk_b = sc.keygen(g=pk_a['g'])
    msg = b"testing testing"

    ciphertext = sc.signcrypt(pk_b, sk_a, msg)
    valid, unsigncrypt = sc.unsigncrypt(pk_a, sk_b, ciphertext)
    assert unsigncrypt == msg
    assert valid
group.EndBenchmark()
msmtDict = group.GetGeneralBenchmarks()
print(msmtDict)
