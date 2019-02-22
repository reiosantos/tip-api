

def numbers():
    nums = [x for x in range(1, 101)]
    for number in nums:
        if number % 3 == 0 and number % 5 == 0:
            print("{0} -> fizz buzz".format(number))
        elif number % 3 == 0 and not number % 5 == 0:
            print("{0} -> fizz".format(number))
        elif not number % 3 == 0 and number % 5 == 0:
            print("{0} -> buzz".format(number))


# numbers()


def fibonacci_series(number):
    if number <= 0:
        return 0
    if number == 1:
        return 1
    return fibonacci_series(number - 1) + fibonacci_series(number - 2)


# print(fibonacci_series(7))


def factorial(number):
    if number == 0:
        return 1
    return number * factorial(number-1)

# print(factorial(6))
