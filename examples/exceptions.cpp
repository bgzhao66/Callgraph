#include <cstdio>
#include <stdexcept>

__attribute__((noinline)) void inner()
{
    throw std::runtime_error("boom");
}

__attribute__((noinline)) void middle()
{
    inner();
}

__attribute__((noinline)) void outer()
{
    try {
        middle();
    } catch (const std::exception&) {
    }
}

int main()
{
    outer();
    std::printf("caught\n");
    return 0;
}
