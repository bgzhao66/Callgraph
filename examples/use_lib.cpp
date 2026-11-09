#include <cstdio>
#include <unistd.h>

int foo(int x);

int main()
{
    sleep(1);
    for (int i = 0; i < 3; ++i)
        std::printf("%d\n", foo(i));
    return 0;
}
