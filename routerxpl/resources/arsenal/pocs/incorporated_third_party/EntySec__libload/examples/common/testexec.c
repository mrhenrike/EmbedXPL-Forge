#include <stdio.h>

int main(int argc, char **argv)
{
    printf("[testexec] Hello from in-memory executable!\n");
    printf("[testexec] argc = %d\n", argc);

    for (int i = 0; i < argc; i++)
        printf("[testexec] argv[%d] = %s\n", i, argv[i]);

    return 0;
}
