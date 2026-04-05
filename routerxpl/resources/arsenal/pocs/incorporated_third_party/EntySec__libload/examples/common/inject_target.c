/*
 * inject_target.c — Target process for injection tests
 *
 * Loops for 60 seconds waiting to be injected.
 */

#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("[target] PID=%d\n", getpid());
    fflush(stdout);

    for (int i = 0; i < 60; i++)
        sleep(1);

    return 0;
}
