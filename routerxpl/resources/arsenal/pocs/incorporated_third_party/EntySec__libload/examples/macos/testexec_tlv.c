/*
 * testexec_tlv.c — test Thread-Local Variables via reflective loading
 *
 * Exercises __thread variables (initialized, zero-init, multiple)
 * to verify the TLV thunk and per-thread allocation work correctly.
 */

#include <stdio.h>

static __thread int    tlv_counter = 42;
static __thread int    tlv_zero;
static __thread double tlv_pi = 3.14159;
static __thread char   tlv_buf[64];

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int pass = 1;

    /* Check initialized TLV */
    if (tlv_counter != 42)
    {
        printf("[FAIL] tlv_counter: expected 42, got %d\n", tlv_counter);
        pass = 0;
    }

    /* Check zero-init TLV */
    if (tlv_zero != 0)
    {
        printf("[FAIL] tlv_zero: expected 0, got %d\n", tlv_zero);
        pass = 0;
    }

    /* Check double TLV */
    if (tlv_pi < 3.14 || tlv_pi > 3.15)
    {
        printf("[FAIL] tlv_pi: expected ~3.14159, got %f\n", tlv_pi);
        pass = 0;
    }

    /* Check zero-init buffer */
    int buf_ok = 1;
    for (int i = 0; i < 64; i++)
    {
        if (tlv_buf[i] != 0)
        {
            buf_ok = 0;
            break;
        }
    }
    if (!buf_ok)
    {
        printf("[FAIL] tlv_buf: not zero-initialized\n");
        pass = 0;
    }

    /* Mutate and verify */
    tlv_counter = 100;
    tlv_zero = 999;
    tlv_pi = 2.71828;
    tlv_buf[0] = 'A';

    if (tlv_counter != 100 || tlv_zero != 999 ||
        tlv_pi < 2.71 || tlv_pi > 2.72 || tlv_buf[0] != 'A')
    {
        printf("[FAIL] TLV mutation check failed\n");
        pass = 0;
    }

    if (pass)
        printf("[PASS] All TLV tests passed\n");

    return pass ? 0 : 1;
}
