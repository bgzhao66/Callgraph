#include <csetjmp>
#include <cstdio>

static std::jmp_buf jump_target;

// Recurses a little so that each error leaves several frames behind.
__attribute__((noinline)) void deep(int depth)
{
    if (depth == 0)
        longjmp(jump_target, 1);
    deep(depth - 1);
}

__attribute__((noinline)) void error_path()
{
    deep(6);
}

int main()
{
    // The jump target stays live across all attempts, like PostgreSQL's
    // sigsetjmp in PostgresMain.  Without stack-pointer resynchronisation the
    // abandoned frames would accumulate on every iteration.
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (setjmp(jump_target) == 0)
            error_path();
    }

    std::printf("done\n");
    return 0;
}
