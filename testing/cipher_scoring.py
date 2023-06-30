# Largely inspired by NL Labs' tls checks for Internet.nl


from collections import OrderedDict
from enum import Enum
from math import log, pow


class SecLevel(Enum):
    GOOD = 3
    SUFFICIENT = 2
    PHASE_OUT = 1
    INSUFFICIENT = 0
    UNKNOWN = -1


class CipherScoreAndSecLevel:
    @staticmethod
    def get_score_header():
        return "DHEAERKKKKKKKKKKKKKKKKHHHHHHHHHHHHHHHHAC"

    @staticmethod
    def get_subscore_ecdsa_rsa(ci):
        if ci.tls_version == "TLSv1.3":
            return 1, SecLevel.GOOD
        else:
            return {"ECDSA": (2, SecLevel.GOOD), "RSA": (1, SecLevel.GOOD)}.get(
                ci.auth_algorithm, (0, SecLevel.INSUFFICIENT)
            )

    @staticmethod
    def get_subscore_mac_alg(ci):
        return {
            "MD5": SecLevel.INSUFFICIENT,
            "SHA1": SecLevel.SUFFICIENT,
        }.get(ci.hash_algorithm, SecLevel.GOOD)

    @staticmethod
    def get_subscore_aead(ci):
        return {
            "AEAD": (1, SecLevel.GOOD),
        }.get(ci.hash_algorithm, SecLevel.UNKNOWN)

    @staticmethod
    def get_subscore_ecdhe_dhe(ci):
        DHE_TERMS = frozenset(["DHE", "EDH"])
        ECDHE_TERMS = frozenset(["ECDHE", "EECDH"])

        def contains(haystack, needles):
            return len([x for x in needles if x in haystack]) > 0

        if ci.tls_version == "TLSv1.3":
            return 3, SecLevel.GOOD

        elif "ECDH" in ci.kex_algorithm:
            return {
                False: (2, SecLevel.INSUFFICIENT),
                True: (4, SecLevel.GOOD),
            }.get(contains(ci.name, ECDHE_TERMS))
        elif "DH" in ci.kex_algorithm:
            return {
                False: (1, SecLevel.INSUFFICIENT),
                True: (3, SecLevel.SUFFICIENT),
            }.get(contains(ci.name, DHE_TERMS))
        elif "RSA" in ci.kex_algorithm:
            return 0, SecLevel.PHASE_OUT
        else:
            return 0, SecLevel.INSUFFICIENT

    @staticmethod
    def get_subscore_bulk_enc_alg(ci):
        if "AES 256" in ci.enc_algorithm:
            score = 2
        elif "CHACHA20" in ci.enc_algorithm:
            score = 1
        else:
            score = 0
        if (
            (ci.enc_algorithm == "AES 256 GCM")
            or (ci.enc_algorithm == "CHACHA20 POLY1305")
            or (ci.enc_algorithm == "AES 128 GCM")
            or (ci.enc_algorithm == "AES 256 CCM")
            or (ci.enc_algorithm == "AES 128 CCM")
        ):
            sec_level = SecLevel.GOOD
        elif (
            ("AES 256" in ci.enc_algorithm)
            or ("AES 128" in ci.enc_algorithm)
            or (ci.enc_algorithm == "Camellia")
        ):
            sec_level = SecLevel.SUFFICIENT
        elif (
            (ci.enc_algorithm == "3DES")
            or (ci.enc_algorithm == "SEED")
            or (ci.enc_algorithm == "CHACHA20" and "CHACHA20_POLY1305_OLD" in ci.name)
            or ("ARIA" in ci.enc_algorithm and "GCM" in ci.enc_algorithm)
        ):
            sec_level = SecLevel.PHASE_OUT
        else:
            sec_level = SecLevel.INSUFFICIENT

        return score, sec_level

    @staticmethod
    def get_subscore_hash_size(ci):
        return {
            "SHA224": (224, SecLevel.SUFFICIENT),
            "SHA256": (256, SecLevel.GOOD),
            "SHA384": (384, SecLevel.GOOD),
            "SHA512": (512, SecLevel.GOOD),
            None: (0, SecLevel.GOOD),
        }.get(ci.hash_algorithm, (160, SecLevel.PHASE_OUT))

    @staticmethod
    def determine_appendix_c_sec_level(ci):
        counts = OrderedDict()
        counts[SecLevel.GOOD] = 0
        counts[SecLevel.SUFFICIENT] = 0
        counts[SecLevel.PHASE_OUT] = 0
        counts[SecLevel.INSUFFICIENT] = 0
        counts[SecLevel.UNKNOWN] = 0

        counts[CipherScoreAndSecLevel.get_subscore_ecdsa_rsa(ci)[1]] += 1
        counts[CipherScoreAndSecLevel.get_subscore_ecdhe_dhe(ci)[1]] += 1
        counts[CipherScoreAndSecLevel.get_subscore_bulk_enc_alg(ci)[1]] += 1
        counts[CipherScoreAndSecLevel.get_subscore_mac_alg(ci)] += 1

        for sec_level in reversed(counts.keys()):
            if counts[sec_level]:
                return sec_level

        return SecLevel.UNKNOWN

    @staticmethod
    def calc_cipher_score(ci):
        return (
            (CipherScoreAndSecLevel.get_subscore_ecdhe_dhe(ci)[0] << 37)
            | (CipherScoreAndSecLevel.get_subscore_aead(ci)[0] << 36)
            | (CipherScoreAndSecLevel.get_subscore_ecdsa_rsa(ci)[0] << 34)
            | (CipherScoreAndSecLevel.get_subscore_hash_size(ci)[0] << 2)
            | (CipherScoreAndSecLevel.get_subscore_bulk_enc_alg(ci)[0])
        )

    @staticmethod
    def format_score(score):
        return format(score, "040b")

    @staticmethod
    def is_in_seclevel_order(seclevel1, seclevel2):
        return seclevel1.value >= seclevel2.value

    @staticmethod
    def is_in_prescribed_order(score1, score2):
        if score1 is None or score2 is None:
            raise ValueError
        return True

    @staticmethod
    def get_violated_rule_number(score1, score2):
        def get_highest_set_bit(n):
            return -1 if n == 0 else int(log(n, 2))

        if score1 == score2:
            raise ValueError
        highestbit = None
        while not highestbit:
            highbit1 = get_highest_set_bit(score1)
            highbit2 = get_highest_set_bit(score2)
            if highbit1 == highbit2:
                bit_mask_to_keep_only_bits_below_highbit = int(pow(2, highbit1)) - 1
                score1 &= bit_mask_to_keep_only_bits_below_highbit
                score2 &= bit_mask_to_keep_only_bits_below_highbit
            else:
                highestbit = max(highbit1, highbit2)
        if highestbit >= 37:
            return 1
        elif highestbit >= 36:
            return 2
        elif highestbit >= 34:
            return 3
        elif highestbit >= 2:
            return 4
        else:
            return 5


def load_cipher_info(ciphersuites: list):
    class CipherInfo:
        def __init__(self, ciphersuite):
            self.name = ciphersuite["name"]
            self.tls_version = ciphersuite["tls_version"]
            self.kex_algorithm = ciphersuite["kex_algorithm"]
            self.auth_algorithm = ciphersuite["auth_algorithm"]
            self.enc_algorithm = ciphersuite["enc_algorithm"]
            self.hash_algorithm = ciphersuite["hash_algorithm"]
            self.sec_level = None

        def __dict__(self):
            return {
                "name": self.name,
                "tls_version": self.tls_version,
                "kex_algorithm": self.kex_algorithm,
                "auth_algorithm": self.auth_algorithm,
                "enc_algorithm": self.enc_algorithm,
                "hash_algorithm": self.hash_algorithm,
                "sec_level": self.sec_level,
            }

    result = dict()
    for ciphersuite in ciphersuites:
        lowest_sec_level = 3
        if ciphersuite["name"] not in result:
            ci = CipherInfo(ciphersuite)
            sec_level = CipherScoreAndSecLevel.determine_appendix_c_sec_level(ci)
            ci.sec_level = {"level": sec_level.name, "score": sec_level.value}
            result[ciphersuite["name"]] = ci.__dict__()
            if sec_level.value < lowest_sec_level:
                lowest_sec_level = sec_level.value
    return {
        "result": result,
        "lowest_sec_level": str(SecLevel(lowest_sec_level)).split(".")[1],
    }
