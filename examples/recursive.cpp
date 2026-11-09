#include <cstdio>

__attribute__((noinline)) int factorial(int n)
{
    if (n <= 1)
        return 1;
    return n * factorial(n - 1);
}

int main()
{
    std::printf("%d\n", factorial(3));
    return 0;
}
