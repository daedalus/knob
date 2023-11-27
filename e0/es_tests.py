"""
es_tests.py

"""

from es import *

from subprocess import call
import pprint

def test_Kc(name, g1, g2, Kc, Kc_mod_g1, Kc_prime):
    """Test from test vector the reverse computation of Kc."""

    quotient, remainder = Kc_prime.gf_divide_by_modulus(g2, 128)
    assert(int(quotient) == int(Kc_mod_g1))
    log.debug(f'int(quotient): {int(quotient)}')
    log.debug(f'int(remainder): {int(remainder)}')

    mi = quotient.gf_MI(g1, 128)
    quotient2, remainder2 = quotient.gf_divide_by_modulus(g1, 128)
    mi2 = quotient.multiplicative_inverse(g1)
    log.debug(f'int(Kc): {int(Kc)}')
    try:
        assert(int(mi2) == int(Kc))
    except Exception:
        if mi2 is not None:
            log.debug(f'int(mi2): {int(mi2)}')
        else:
            log.debug('mi2 is None')
        log.debug('Fail mi2')
    try:
        assert(int(mi) == int(Kc))
    except Exception:
        log.debug(f'int(mi): {int(mi)}')
        log.debug('Fail mi')
    try:
        assert(int(remainder2) == int(Kc))
    except Exception:
        log.debug(f'int(remainder2): {int(remainder2)}')
        log.debug('Fail remainder2')
    try:
        assert(int(quotient2) == int(Kc))
    except Exception:
        log.debug(f'int(quotient2): {int(quotient2)}')
        log.debug('Fail quotient2')

    # one = BitVector(intVal=0x01, size=128)
    # r = Kc_prime.gf_MI(kkj, 128)
    # quotient, remainder = r.gf_divide_by_modulus(g1, 128)
    # r = Kc.gf_multiply_modular(one, g1, 128)
    # emsg = "{} Kc mod g1: {} is not equal to {}".format(name, int(r), int(Kc_mod_g1))
    # assert int(r) == int(Kc_mod_g1), emsg

    # r = g2.gf_multiply(Kc_mod_g1)
    # emsg = "{} g2 * Kc_mod_g1: {} is not equal to {}".format(name, int(r), int(Kc_prime))
    # assert int(r) == int(Kc_prime), emsg


def test_g1_g2():
    # NOTE: L=1
    g1  = BitVector(intVal=0x011d, size=128)
    g1_t = BitVector(intVal=G1[1], size=128)
    assert int(g1) == int(g1_t)
    g2 = BitVector(intVal=0x00e275a0abd218d4cf928b9bbf6cb08f, size=128)
    g2_t = BitVector(intVal=G2[1], size=128)
    assert int(g2) == int(g2_t)

    # NOTE: L=2
    g1 = BitVector(intVal=0x0001003f, size=128)
    g1_t = BitVector(intVal=G1[2], size=128)
    assert int(g1) == int(g1_t)
    g2 = BitVector(intVal=0x01e3f63d7659b37f18c258cff6efef, size=128)
    g2_t = BitVector(intVal=G2[2], size=128)
    assert int(g2) == int(g2_t)


def test_Kc_prime_bit_vec():

    log.debug("Kc_prime(x) = g2(x) (Kc(x) mod g1(x))")
    one = BitVector(intVal=0x01, size=128)

    # NOTE: L=1
    g1 = BitVector(intVal=G1[1], size=128)
    g2 = BitVector(intVal=G2[1], size=128)
    Kc = BitVector(intVal=0xa2b230a493f281bb61a85b82a9d4a30e, size=128)
    Kc_prime = BitVector(intVal=0x7aa16f3959836ba322049a7b87f1d8a5, size=128)
    Kc_mod_g1 = BitVector(intVal=0x9f, size=128)

    Kc_mod_g1_t = Kc.gf_multiply_modular(one, g1, 128)
    assert Kc_mod_g1_t == Kc_mod_g1
    # NOTE: mutiplication increase the size of the vector
    Kc_prime_t = g2.gf_multiply(Kc_mod_g1)[128:]
    assert Kc_prime_t == Kc_prime


    # NOTE: L=2
    g1 = BitVector(intVal=G1[2], size=128)
    g2 = BitVector(intVal=G2[2], size=128)
    Kc = BitVector(intVal=0x64e7df78bb7ccaa4614331235b3222ad, size=128)
    Kc_mod_g1 = BitVector(intVal=0x00001ff0, size=128)
    Kc_prime = BitVector(intVal=0x142057bb0bceac4c58bd142e1e710a50, size=128)

    Kc_mod_g1_t = Kc.gf_multiply_modular(one, g1, 128)
    assert Kc_mod_g1_t == Kc_mod_g1
    # NOTE: mutiplication increase the size of the vector
    Kc_prime_t = g2.gf_multiply(Kc_mod_g1)[128:]
    assert Kc_prime_t == Kc_prime


def test_Kc_prime():

    """pag 1511 L1 means that Kc negotiation ended up with L=1"""

    Kc       = bytearray.fromhex('a2b230a493f281bb61a85b82a9d4a30e')
    Kc_prime = bytearray.fromhex('7aa16f3959836ba322049a7b87f1d8a5')
    rv = Kc_to_Kc_prime(Kc, 1)
    log.debug(f'test_Kc_prime L=1 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=1 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('64e7df78bb7ccaa4614331235b3222ad')
    Kc_prime = bytearray.fromhex('142057bb0bceac4c58bd142e1e710a50')
    rv = Kc_to_Kc_prime(Kc, 2)
    log.debug(f'test_Kc_prime L=2 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=2 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('575e5156ba685dc6112124acedb2c179')
    Kc_prime = bytearray.fromhex('d56d0adb8216cb397fe3c5911ff95618')
    rv = Kc_to_Kc_prime(Kc, 3)
    log.debug(f'test_Kc_prime L=3 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=3 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('8917b4fc403b6db21596b86d1cb8adab')
    Kc_prime = bytearray.fromhex('91910128b0e2f5eda132a03eaf3d8cda')
    rv = Kc_to_Kc_prime(Kc, 4)
    log.debug(f'test_Kc_prime L=4 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=4 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('785c915bdd25b9c60102ab00b6cd2a68')
    Kc_prime = bytearray.fromhex('6fb5651ccb80c8d7ea1ee56df1ec5d02')
    rv = Kc_to_Kc_prime(Kc, 5)
    log.debug(f'test_Kc_prime L=5 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=5 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('5e77d19f55ccd7d5798f9a323b83e5d8')
    Kc_prime = bytearray.fromhex('16096bcbafcf8def1d226a1b4d3f9a3d')
    rv = Kc_to_Kc_prime(Kc, 6)
    log.debug(f'test_Kc_prime L=6 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=6 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('05454e038ddcfbe3ed024b2d92b7f54c')
    Kc_prime = bytearray.fromhex('50f9c0d4e3178da94a09fe0d34f67b0e')
    rv = Kc_to_Kc_prime(Kc, 7)
    log.debug(f'test_Kc_prime L=7 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=7 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('7ce149fcf4b38ad72a5d8a41eb15ba31')
    Kc_prime = bytearray.fromhex('532c36d45d0954e0922989b6826f78dc')
    rv = Kc_to_Kc_prime(Kc, 8)
    log.debug(f'test_Kc_prime L=8 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=8 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('5eeff7ca84fc27829c0517263df6f36e')
    Kc_prime = bytearray.fromhex('016313f60d3771cf7f8e4bb94aa6827d')
    rv = Kc_to_Kc_prime(Kc, 9)
    log.debug(f'test_Kc_prime L=9 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=9 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('7b13846e88beb4de34e7160afd44dc65')
    Kc_prime = bytearray.fromhex('023bc1ec34a0029ef798dcfb618ba58d')
    rv = Kc_to_Kc_prime(Kc, 10)
    log.debug(f'test_Kc_prime L=10 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=10 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('bda6de6c6e7d757e8dfe2d499a181193')
    Kc_prime = bytearray.fromhex('022e08a93aa51d8d2f93fa7885cc1f87')
    rv = Kc_to_Kc_prime(Kc, 11)
    log.debug(f'test_Kc_prime L=11 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=11 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('e6483b1c2cdb10409a658f97c4efd90d')
    Kc_prime = bytearray.fromhex('030d752b216fe29bb880275cd7e6f6f9')
    rv = Kc_to_Kc_prime(Kc, 12)
    log.debug(f'test_Kc_prime L=12 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=12 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('d79d281da22668476b223c46dc0ab9ee')
    Kc_prime = bytearray.fromhex('03f111389cebf91900b938084ac158aa')
    rv = Kc_to_Kc_prime(Kc, 13)
    log.debug(f'test_Kc_prime L=13 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=13 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('cad9a65b9fca1c1da2320fcf7c4ae48e')
    Kc_prime = bytearray.fromhex('284840fdf1305f3c529f570376adf7cf')
    rv = Kc_to_Kc_prime(Kc, 14)
    log.debug(f'test_Kc_prime L=14 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=14 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime

    Kc       = bytearray.fromhex('21f0cc31049b7163d375e9e106029809')
    Kc_prime = bytearray.fromhex('7f10b53b6df84b94f22e566a3754a37e')
    rv = Kc_to_Kc_prime(Kc, 15)
    log.debug(f'test_Kc_prime L=15 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=15 Kc_prime: {repr(Kc_prime)}')
    assert rv == Kc_prime


    log.debug('e0_tests If L=16 then Kc_prime equals Kc')
    Kc       = bytearray.fromhex('35ec8fc3d50ccd325f2fd907bde206de')
    Kc_prime = bytearray.fromhex('35ec8fc3d50ccd325f2fd907bde206de')
    rv = Kc_to_Kc_prime(Kc, 16)
    log.debug(f'test_Kc_prime L=16 rv      : {repr(rv)}')
    log.debug(f'test_Kc_prime L=16 Kc_prime: {repr(Kc_prime)}')
    assert Kc == Kc_prime
    assert rv == Kc_prime


def test_Kc_prime_entropy1():
    """Fix Kc vary L"""

    Kc       = bytearray.fromhex('aaaabbbbccccddddeeee000011112222')
    rv = list(range(18))
    for i in range(1, 17):
        rv[i] = Kc_to_Kc_prime(Kc, i)
    log.info(f'test_Kc_prime_entropy1 Kc       : {repr(Kc)}')
    log.info(f'test_Kc_prime_entropy1 L=1      : {repr(rv[1])}')
    log.info(f'test_Kc_prime_entropy1 L=2      : {repr(rv[2])}')
    log.info(f'test_Kc_prime_entropy1 L=3      : {repr(rv[3])}')
    log.info(f'test_Kc_prime_entropy1 L=4      : {repr(rv[4])}')
    log.info(f'test_Kc_prime_entropy1 L=5      : {repr(rv[5])}')
    log.info(f'test_Kc_prime_entropy1 L=6      : {repr(rv[6])}')
    log.info(f'test_Kc_prime_entropy1 L=7      : {repr(rv[7])}')
    log.info(f'test_Kc_prime_entropy1 L=8      : {repr(rv[8])}')
    log.info(f'test_Kc_prime_entropy1 L=9      : {repr(rv[9])}')
    log.info(f'test_Kc_prime_entropy1 L=10     : {repr(rv[10])}')
    log.info(f'test_Kc_prime_entropy1 L=11     : {repr(rv[11])}')
    log.info(f'test_Kc_prime_entropy1 L=12     : {repr(rv[12])}')
    log.info(f'test_Kc_prime_entropy1 L=13     : {repr(rv[13])}')
    log.info(f'test_Kc_prime_entropy1 L=14     : {repr(rv[14])}')
    log.info(f'test_Kc_prime_entropy1 L=15     : {repr(rv[15])}')
    log.info(f'test_Kc_prime_entropy1 L=16     : {repr(rv[16])}')


def test_Kc_prime_entropy2():
    """Fix L vary Kc Byte by Byte"""

    zero           = bytearray.fromhex('00000000000000000000000000000000')
    almost_one     = bytearray('\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')
    Kc       = bytearray.fromhex('00001111222233334444555566667777')
    # log.info('test_Kc_prime_entropy2 Kc    : {}'.format(repr(Kc)))

    L = 1
    for l in range(2,17):
        L = l
        filename = f'kcs/L{L}-00001111222233334444555566667777.txt'
        with open(filename, mode="w") as fp:
            fp.write(f'test_Kc_prime_entropy2 Kc                  :{repr(Kc)}\n')
            for j in range(16):  # 0--15
                rv = {}
                zeros = []
                almost_ones = []
                BYTE_INDEX = j
                for i in range(256):  # 0..256
                    Kc[BYTE_INDEX] = i
                    # log.info('test_Kc_prime_entropy2 Kc[{}]: {}'.format(BYTE_INDEX, i))
                    rv[i] = Kc_to_Kc_prime(Kc, L)
                    if rv[i] == zero:
                        zeros.append(i)
                    elif rv[i] == almost_one:
                        almost_ones.append(i)

                fp.write(f'test_Kc_prime_entropy2 BEGIN BYTE_INDEX: {BYTE_INDEX}\n')
                # log.info('test_Kc_prime_entropy2 zeros : {}'.format(repr(zeros)))
                fp.write(f'test_Kc_prime_entropy2 zeros           : {repr(zeros)}\n')
                # log.info('test_Kc_prime_entropy2 almost_ones : {}'.format(repr(almost_ones)))
                fp.write(f'test_Kc_prime_entropy2 almost_ones     : {repr(almost_ones)}\n')
                rvp = pprint.pformat(rv, 4)
                # log.info('test_Kc_prime_entropy2 Kc        : {}'.format(rvp))
                fp.write(f'test_Kc_prime_entropy2 Kc_prime        : {rvp}\n')
                fp.write(f'test_Kc_prime_entropy2 END BYTE_INDEX  : {BYTE_INDEX}\n\n')
                print(f'{filename} BYTE_INDEX {j} zeros: {zeros}, almost_ones: {almost_ones}')
        # print('Output of: cat {}'.format(filename))
        # call(["cat", filename])


if __name__ == '__main__':

    test_g1_g2()
    test_Kc_prime_bit_vec()
    test_Kc_prime()
    log.setLevel(logging.INFO)

    # test_Kc_prime_entropy1()
    # test_Kc_prime_entropy2()



