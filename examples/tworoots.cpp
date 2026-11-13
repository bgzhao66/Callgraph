#include <cstdio>
#include <thread>

__attribute__((noinline)) int leaf(int x)
{
    return x + 1;
}

__attribute__((noinline)) int task_a(int x)
{
    return leaf(x);
}

__attribute__((noinline)) int task_b(int x)
{
    return leaf(x + 1);
}

int main()
{
    // The worker is not traced, so task_a() and task_b() are independent
    // roots in the same thread.  Used by the --histogram pairing test.
    std::thread worker([] {
        std::printf("%d %d\n", task_a(1), task_b(2));
    });
    worker.join();
    return 0;
}
