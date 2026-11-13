// Stackful coroutine built on ucontext.  The fiber runs on its own mmap'd
// stack, so the per-thread shadow stack sees a stack region that is unrelated
// to the main stack.
#include <sys/mman.h>
#include <ucontext.h>

#include <cstdio>

static ucontext_t main_ctx, fiber_ctx;
static char* fiber_stack;

__attribute__((noinline)) void leaf() { std::printf("leaf\n"); }

__attribute__((noinline)) void fiber_body()
{
    leaf();
    swapcontext(&fiber_ctx, &main_ctx);
    leaf();
}

int main()
{
    fiber_stack = static_cast<char*>(mmap(nullptr, 1 << 20,
                                          PROT_READ | PROT_WRITE,
                                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
                                          -1, 0));
    if (fiber_stack == MAP_FAILED)
        return 1;

    getcontext(&fiber_ctx);
    fiber_ctx.uc_stack.ss_sp = fiber_stack;
    fiber_ctx.uc_stack.ss_size = 1 << 20;
    fiber_ctx.uc_link = &main_ctx;
    makecontext(&fiber_ctx, reinterpret_cast<void (*)()>(fiber_body), 0);

    swapcontext(&main_ctx, &fiber_ctx);  // run the fiber until it suspends
    leaf();                              // traced call on the main stack
    swapcontext(&main_ctx, &fiber_ctx);  // let the fiber finish
    return 0;
}
