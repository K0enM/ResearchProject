from charm.toolbox.integergroup import IntegerGroupQ
from charm.toolbox.conversion import Conversion
import charm.toolbox.symcrypto as symcrypto


class Signcryption():
    el = None
    debug = False
    group = None

    def __init__(self, p=0, q=0, bits=1024, debug=False):
        self.cipher = None
        self.debug = debug
        self.group = IntegerGroupQ()
        if p == 0 or q == 0:
            self.group.paramgen(bits)
        else:
            self.group.p, self.group.q = p, q
        if debug:
            print(f'p => {self.group.p}')
            print(f'q => {self.group.q}')

    def keygen(self, g=None):
        x = self.group.random()
        if g is not None:
            g = g
        else:
            g = self.group.randomGen()
        h = (g ** x)
        if self.debug:
            print('--- Public Parameter ---')
            print(f"h => {h}")
            print(f"g => {g}\n")
            print('--- Secret key ---')
            print(f"x => {x}\n")
        return ({'h': h, 'g': g}, {'x': x})

    def signcrypt(self, public_key, private_key, M):
        x = self.group.random(max=self.group.q)
        k = public_key['h'] ** x
        r = self.group.hash((k, M))
        s = x / (r + private_key['x']) % self.group.q
        self.cipher = symcrypto.SymmetricCryptoAbstraction(Conversion.IP2OS(k))
        c = self.cipher.encrypt(M)

        if self.debug:
            print(f'x => {x}\n')
            print(f'k => {k}\n')
            print(f'r => {r}\n')
            print(f's => {s}\n')
            print(f'c => {c}\n')

        return ({'c': c, 'r': r, 's': s})

    def unsigncrypt(self, pk, sk, C):
        k = (pk['h'] * (pk['g'] ** C['r'])) ** (C['s'] * sk['x'])
        self.cipher = symcrypto.SymmetricCryptoAbstraction(Conversion.IP2OS(k))
        m = self.cipher.decrypt(C['c'])
        e = self.group.hash((k, m))

        if self.debug:
            print(f'k => {k}\n')
            print(f'm => {m}\n')
            print(f'e => {e}\n')

        return e == C['r'], m


if __name__ == "__main__":
    signcrypt = Signcryption(bits=256, debug=False)
    pk_a, sk_a = signcrypt.keygen()
    pk_b, sk_b = signcrypt.keygen(g=pk_a['g'])

    msg = b"test"
    C = signcrypt.signcrypt(pk_b, sk_a, msg)
    valid, received = signcrypt.unsigncrypt(pk_a, sk_b, C)
    print(valid)
    assert msg == received
    assert valid