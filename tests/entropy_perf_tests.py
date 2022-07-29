from logic.randomness import RandTest
from misc import utils

STOP = 30_000


def entropy_tests():
    for i in range(1, STOP):
        RandTest.calc_entropy_test("1234567890ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghilmnopqrstuvzjkwzx" * 1000, False)

def entropy_aprox_tests1():
    for i in range(1, STOP):
        RandTest.calc_aprox_entropy_test1("1234567890ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghilmnopqrstuvzjkwzx" * 1000)

def entropy_one_aprox_test():
    h = RandTest.calc_aprox_entropy_test1("1234567890ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghilmnopqrstuvzjkwzx" * 1000)
    print("aprox h: " + str(h))


def entropy_one_test():
    h = RandTest.calc_entropy_test("1234567890ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghilmnopqrstuvzjkwzx" * 1000, False)
    print("exact h: " + str(h))


if __name__ == "__main__":
    # entropy_one_test()
    # entropy_one_aprox_test()

    print("Entropy Test")
    with utils.Timer(verbose=True):
        entropy_tests()

    print("Approximated Entropy Test 1")
    with utils.Timer(verbose=True):
        entropy_aprox_tests1()
