from charm.toolbox.ecgroup import ECGroup, G, ZR
from charm.toolbox.eccurve import prime192v1
import charm.toolbox.symcrypto as symcrypto
from charm.toolbox.conversion import Conversion


class SigncryptionEcc():
    def __init__(self, curve, debug=False):
        self.group = ECGroup(curve)
        self.debug = debug

    def keygen(self, g=None):
        if g is not None:
            g = g
        else:
            g = self.group.random(G)
        x = self.group.random(ZR)
        h = g ** x
        q = self.group.order()
        if self.debug:
            print(f'g => {g}\n')
            print(f'x => {x}\n')
            print(f'h => {h}\n')
            print(f'q => {q}\n')
        return {'g': g, 'h': h, 'q': q}, {'x': x}

    def signcrypt(self, pk, sk, m):
        v = self.group.random(ZR)
        k = self.group.hash(pk['h'] ** v)
        cipher = symcrypto.SymmetricCryptoAbstraction(Conversion.IP2OS(int(k)))
        c = cipher.encrypt(m)
        r = self.group.hash((k, m))
        a = (sk['x'] + r) ** -1
        s = (v * a)
        if self.debug:
            print(f'v => {v}\n')
            print(f'k => {k}\n')
            print(f'c => {c}\n')
            print(f'r => {r}\n')
            print(f's => {s}\n')
        return {'c': c, 'r': r, 's': s}

    def unsigncrypt(self, pk, sk, C):
        u = (C['s'] * sk['x'])
        u1 = pk['h'] ** u
        u2 = pk['g'] ** (u * C['r'])
        k = self.group.hash(u1 * u2)
        cipher = symcrypto.SymmetricCryptoAbstraction(Conversion.IP2OS(int(k)))
        m = cipher.decrypt(C['c'])
        e = self.group.hash((k, m))

        if self.debug:
            print(f'u => {u}\n')
            print(f'u1 => {u1}\n')
            print(f'u2 => {u2}\n')
            print(f'k => {k}\n')
            print(f'm => {m}\n')
            print(f'valid => {e == C["r"]}\n')
        return e == C['r'], m
