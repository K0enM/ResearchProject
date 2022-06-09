import os
import pickle


from charm.schemes.pkenc.pkenc_rsa import RSA_Enc, RSA_Sig

rsa_enc = RSA_Enc()
rsa_sig = RSA_Sig()
trials = 20

for i in range(trials):
    pk_sig, sk_sig = rsa_sig.keygen(secparam=128)
    pk_enc, sk_enc = rsa_enc.keygen(secparam=2048)


    msg = os.urandom(20)
    original_len = len(msg)
    print(original_len)

    S = rsa_sig.sign(sk=sk_sig, M=msg)
    ciphertext = rsa_enc.encrypt(pk_enc, msg)
    message_len = len(pickle.dumps(int(ciphertext)))
    print(message_len)
    unencrypted = rsa_enc.decrypt(pk_enc, sk_enc, ciphertext)
    assert msg == unencrypted
    assert rsa_sig.verify(pk_sig, unencrypted, S)
    print(f'Message overhead iteration {i} is: {((message_len - original_len) / original_len) * 100}%')

