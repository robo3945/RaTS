import math

from logic.randomness import RandEntropyTest, RandMonobitTest
from misc import utils

STOP = 30_000

def get_entropy(data):
    # returns: float (between 0 and 8)
    # a higher entropy value indicates more randomness in the data

    # store the number of times each byte appears in the data
    p = {}
    for x in data:
        if x not in p:
            p[x] = 0
        p[x] += 1
    # total number of bytes in the data
    total = sum(p.values())

    entropy = 0
    # entropy of the data by iterating over the dictionary
    for x in p:
        p[x] /= total
        entropy -= p[x] * math.log2(p[x])
    return entropy


def entropy_tests():
    for i in range(1, STOP):
        RandEntropyTest.calc_rand_idx("1234567890ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghilmnopqrstuvzjkwzx" * 1000, False)


def entropy_tests_1():
    for i in range(1, STOP):
        get_entropy("1234567890ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghilmnopqrstuvzjkwzx" * 1000)


def entropy_monobit_test():
    h = RandMonobitTest.calc_rand_idx(
        bytes("1234567890ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghilmnopqrstuvzjkwzx", 'UTF-8') * 2)
    print("aprox h: " + str(h))


def entropy_one_test():
    h = RandEntropyTest.calc_rand_idx("1234567890ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghilmnopqrstuvzjkwzx" * 1000, False)
    print("exact h: " + str(h))


if __name__ == "__main__":
    # entropy_one_test()
    entropy_monobit_test()

    print("Entropy Test")
    with utils.Timer(verbose=True):
        entropy_tests()
    with utils.Timer(verbose=True):
        entropy_tests_1()

"""
    print("Approximated Entropy Test 1")
    with utils.Timer(verbose=True):
        entropy_aprox_tests()
"""
