#include <cstdio>

__attribute__((noinline)) int A(int x) { return x + 1; }
__attribute__((noinline)) int B(int x) { return A(x) * 2; }
__attribute__((noinline)) int C(int x) { return B(x) + A(x); }

int main()
{
    std::printf("%d\n", C(3));
    return 0;
}
