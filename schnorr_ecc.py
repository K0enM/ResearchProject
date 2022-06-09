from charm.toolbox.ecgroup import ECGroup, G, ZR
from charm.toolbox.PKSig import PKSig


class SchnorrEcc(PKSig):
    def __init__(self, curve, debug=False):
        PKSig.__init__(self)
        self.group = ECGroup(curve)
        self.debug = debug

    def keygen(self, g=None):
        if g is not None:
            g = g
        else:
            g = self.group.random(G)
        x = self.group.random(ZR)
        q = self.group.order()
        h = g ** x
        return {'g': g, 'h': h, 'q': q}, {'x': x}

    def sign(self, pk, sk, message):
        k = self.group.random(ZR)
        a = pk['g'] ** k
        r = self.group.hash((a, message))
        s = k + r * sk['x']
        return {'r': r, 's': s, 'm': message}

    def verify(self, pk, message, sig):
        r = sig['r']
        a1 = (pk['g'] ** sig['s'])
        print(f'{a1}')
        a2 = (pk['h'] ** r) ** -1
        print(f'{a2}')
        a = a1 * a2
        e = self.group.hash((a, message))

        return e == r


