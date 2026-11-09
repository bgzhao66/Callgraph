#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

__attribute__((noinline)) int leaf(int x)
{
    return x + 1;
}

__attribute__((noinline)) int worker(int id)
{
    int total = 0;
    for (int i = 0; i < 3; ++i)
        total += leaf(id + i);
    return total;
}

int main()
{
    std::vector<std::thread> threads;
    for (int i = 0; i < 2; ++i)
        threads.emplace_back([i] { std::printf("worker %d: %d\n", i, worker(i)); });
    for (auto& thread : threads)
        thread.join();
    return 0;
}
