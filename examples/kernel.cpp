#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int ready = 0;

__attribute__((noinline)) void work(int milliseconds)
{
    usleep(static_cast<useconds_t>(milliseconds) * 1000);
}

__attribute__((noinline)) void lock_work()
{
    pthread_mutex_lock(&mutex);
    usleep(50000);
    pthread_mutex_unlock(&mutex);
}

__attribute__((noinline)) void fsync_work()
{
    const int fd = open("/tmp/callgraph-kernel-events-test",
                        O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0)
        return;
    (void)write(fd, "data", 4);
    (void)fsync(fd);
    (void)close(fd);
}

int main()
{
    pthread_t holder;
    pthread_create(&holder, nullptr, [](void*) -> void* {
        pthread_mutex_lock(&mutex);
        ready = 1;
        usleep(100000);
        pthread_mutex_unlock(&mutex);
        return nullptr;
    }, nullptr);

    while (!ready)
        usleep(1000);

    lock_work();
    work(100);
    fsync_work();

    pthread_join(holder, nullptr);
    return 0;
}
