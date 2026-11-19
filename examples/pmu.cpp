#include <cstdint>

__attribute__((noinline)) uint64_t pmu_work(uint64_t count)
{
    uint64_t value = 1;
    for (uint64_t i = 0; i < count; ++i)
        value = value * 6364136223846793005ULL + 1442695040888963407ULL;
    return value;
}

int main()
{
    volatile uint64_t sink = 0;
    for (int i = 0; i < 8; ++i)
        sink ^= pmu_work(20000000);
    return sink == 0 ? 1 : 0;
}
