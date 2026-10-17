# SIMULATED FIXTURE for Sandtrap: harmless, no real network, reads only fake canary files
"""Pure arithmetic helpers. No I/O, no network, no import-time side effects."""


def add(a, b):
    return a + b


def mul(a, b):
    return a * b


def fact(n):
    if n < 0:
        raise ValueError("fact() undefined for negative numbers")
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result


def demo():
    assert add(2, 3) == 5
    assert mul(2, 3) == 6
    assert fact(5) == 120
    assert fact(0) == 1
    print("tinycalc self-check OK")


if __name__ == "__main__":
    demo()
