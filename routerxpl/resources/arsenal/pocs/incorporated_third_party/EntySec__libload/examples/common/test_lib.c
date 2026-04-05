/*
 * test_lib.c — Shared library for test_open
 *
 * Exports a simple function that test_open resolves via libload_sym.
 */

int test_add(int a, int b)
{
    return a + b;
}
