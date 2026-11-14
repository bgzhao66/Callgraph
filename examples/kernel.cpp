#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
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

__attribute__((noinline)) void memory_work()
{
    constexpr size_t kSize = 1 << 20;
    char* pages = static_cast<char*>(mmap(nullptr, kSize, PROT_READ | PROT_WRITE,
                                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (pages == MAP_FAILED)
        return;
    for (size_t offset = 0; offset < kSize; offset += 4096)
        pages[offset] = static_cast<char>(offset);
    (void)munmap(pages, kSize);
}

__attribute__((noinline)) void network_work()
{
    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return;

    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(9);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    (void)connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    (void)sendto(fd, "x", 1, 0, reinterpret_cast<sockaddr*>(&address),
                 sizeof(address));
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
    memory_work();
    network_work();

    pthread_join(holder, nullptr);
    return 0;
}
