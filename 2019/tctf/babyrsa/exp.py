#!/usr/bin/env sage
# coding=utf-8

from pubkey import P, n, e
# from secret import flag
from os import urandom

# R.<a> = GF(2^2049)

if __name__ == '__main__':
    # ptext = flag + os.urandom(256-len(flag))
    # ctext = encrypt(ptext)
    # with open('flag.enc', 'wb') as f:
    #     f.write(ctext)

    p, q = n.factor()

    s = ((2^821 - 1) * (2^1227 - 1))
    d = Integer(e).inverse_mod(s)

    # test = P('x^5 + x^3 + 1')
    # print(pow(test, e * d, n))
    with open('flag.enc', 'rb') as f:
        ctext = f.read()
    c_int = Integer(ctext.encode('hex'), 16)
    c_poly = P(R.fetch_int(c_int))
    m_poly = pow(c_poly, d, n)
    m_int = R(m_poly).integer_representation()
    print(format(m_int, '0256x').decode('hex'))
