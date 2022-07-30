from logic.randomness import RandTest
from misc import utils

STOP = 30_000


def entropy_tests():
    for i in range(1, STOP):
        RandTest.calc_rand_idx("1234567890ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghilmnopqrstuvzjkwzx" * 1000, False)


def entropy_aprox_tests():
    for i in range(1, STOP):
        RandTest.calc_aprox_entropy_test("1234567890ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghilmnopqrstuvzjkwzx" * 1000)


def entropy_monobit_test():
    h = RandTest.calc_rand_idx(
        bytes("1234567890ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghilmnopqrstuvzjkwzx", 'UTF-8') * 2)
    print("aprox h: " + str(h))


def entropy_one_test():
    h = RandTest.calc_rand_idx("1234567890ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghilmnopqrstuvzjkwzx" * 1000, False)
    print("exact h: " + str(h))


if __name__ == "__main__":
    # entropy_one_test()
    entropy_monobit_test()

    quit()

    print("Entropy Test")
    with utils.Timer(verbose=True):
        entropy_tests()

    print("Approximated Entropy Test 1")
    with utils.Timer(verbose=True):
        entropy_aprox_tests()
