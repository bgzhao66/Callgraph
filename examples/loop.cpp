#include <cstdio>
#include <unistd.h>

__attribute__((noinline)) int tick(int x)
{
    return x + 1;
}

int main()
{
    for (int i = 0; i < 600; ++i) {
        std::printf("%d\n", tick(i));
        std::fflush(stdout);
        sleep(1);
    }
    return 0;
}
