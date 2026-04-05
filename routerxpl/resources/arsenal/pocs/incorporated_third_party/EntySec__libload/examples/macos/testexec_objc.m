/*
 * testexec_objc — Objective-C runtime test for libload
 *
 * Uses the ObjC runtime C API (objc_msgSend, objc_getClass,
 * sel_registerName) to interact with Foundation classes.
 * Foundation is loaded at runtime via dlopen so the only
 * link-time imports are from libobjc and libSystem.
 *
 * This validates that:
 *   - ObjC runtime symbols resolve correctly (import fixups)
 *   - dlopen works from reflectively-loaded code
 *   - objc_msgSend dispatch works with canonical selectors
 *   - @autoreleasepool codegen (push/pop) functions correctly
 *
 * Returns 0 on success, or the number of failed tests.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>

#include <objc/runtime.h>
#include <objc/message.h>

/* ── Helpers ───────────────────────────────────────────────────── */

static int errors;

#define CHECK(cond, fmt, ...)                                       \
    do {                                                            \
        if (cond) {                                                 \
            printf("[objc] PASS: " fmt "\n", ##__VA_ARGS__);        \
        } else {                                                    \
            printf("[objc] FAIL: " fmt "\n", ##__VA_ARGS__);        \
            errors++;                                               \
        }                                                           \
    } while (0)

/* Typed objc_msgSend casts */
typedef id   (*msg_id_cstr)(Class, SEL, const char *);
typedef id   (*msg_id_void)(Class, SEL);
typedef id   (*msg_id_id)(id, SEL, id);
typedef const char *(*msg_cstr)(id, SEL);
typedef unsigned long (*msg_ulong)(id, SEL);
typedef int  (*msg_int)(id, SEL);
typedef void (*msg_void_id)(id, SEL, id);
typedef id   (*msg_id_ptr_ulong)(Class, SEL, id *, unsigned long);
typedef id   (*msg_cls_int)(Class, SEL, int);

/* ── main ──────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    errors = 0;

    printf("[objc] === Objective-C runtime tests ===\n");
    printf("[objc] argc=%d\n", argc);
    for (int i = 0; i < argc; i++)
        printf("[objc] argv[%d]=%s\n", i, argv[i]);

    /* Load Foundation at runtime so its classes are available */
    void *fw = dlopen(
        "/System/Library/Frameworks/Foundation.framework/Foundation",
        RTLD_NOW);
    CHECK(fw != NULL, "dlopen Foundation = %p", fw);
    if (!fw) {
        printf("[objc] FATAL: cannot load Foundation\n");
        return 1;
    }

    @autoreleasepool {

        /* ── 1. ObjC class lookup ─────────────────────────────── */

        Class NSStringClass = objc_getClass("NSString");
        CHECK(NSStringClass != Nil,
              "objc_getClass(\"NSString\") = %p", (void *)NSStringClass);

        Class NSArrayClass = objc_getClass("NSArray");
        CHECK(NSArrayClass != Nil,
              "objc_getClass(\"NSArray\") = %p", (void *)NSArrayClass);

        Class NSNumberClass = objc_getClass("NSNumber");
        CHECK(NSNumberClass != Nil,
              "objc_getClass(\"NSNumber\") = %p", (void *)NSNumberClass);

        Class NSMutableStringClass = objc_getClass("NSMutableString");
        CHECK(NSMutableStringClass != Nil,
              "objc_getClass(\"NSMutableString\") = %p",
              (void *)NSMutableStringClass);

        /* ── 2. Register selectors ────────────────────────────── */

        SEL selUTF8     = sel_registerName("UTF8String");
        SEL selWithUTF8 = sel_registerName("stringWithUTF8String:");
        SEL selLength   = sel_registerName("length");
        SEL selIsEqual  = sel_registerName("isEqualToString:");
        SEL selString   = sel_registerName("string");
        SEL selAppend   = sel_registerName("appendString:");
        SEL selCount    = sel_registerName("count");
        SEL selObjAtIdx = sel_registerName("objectAtIndex:");
        SEL selNumInt   = sel_registerName("numberWithInt:");
        SEL selIntVal   = sel_registerName("intValue");
        SEL selArrObjs  = sel_registerName("arrayWithObjects:count:");

        CHECK(selUTF8 != NULL, "selectors registered");

        /* ── 3. NSString creation ─────────────────────────────── */

        id str = ((msg_id_cstr)objc_msgSend)(
            NSStringClass, selWithUTF8, "Hello from ObjC runtime!");
        CHECK(str != nil, "stringWithUTF8String: returned %p", str);

        const char *cstr = ((msg_cstr)objc_msgSend)(str, selUTF8);
        CHECK(cstr && strcmp(cstr, "Hello from ObjC runtime!") == 0,
              "NSString = \"%s\"", cstr ? cstr : "(null)");

        /* ── 4. NSString length ───────────────────────────────── */

        unsigned long len = ((msg_ulong)objc_msgSend)(str, selLength);
        CHECK(len == 24, "NSString length = %lu", len);

        /* ── 5. NSNumber ──────────────────────────────────────── */

        id num = ((msg_cls_int)objc_msgSend)(NSNumberClass, selNumInt, 42);
        CHECK(num != nil, "numberWithInt:42 = %p", num);

        int ival = ((msg_int)objc_msgSend)(num, selIntVal);
        CHECK(ival == 42, "NSNumber intValue = %d", ival);

        /* ── 6. NSArray creation ──────────────────────────────── */

        id nums[3];
        nums[0] = ((msg_cls_int)objc_msgSend)(NSNumberClass, selNumInt, 10);
        nums[1] = ((msg_cls_int)objc_msgSend)(NSNumberClass, selNumInt, 20);
        nums[2] = ((msg_cls_int)objc_msgSend)(NSNumberClass, selNumInt, 30);

        id array = ((msg_id_ptr_ulong)objc_msgSend)(
            NSArrayClass, selArrObjs, nums, 3);
        CHECK(array != nil, "NSArray created = %p", array);

        unsigned long cnt = ((msg_ulong)objc_msgSend)(array, selCount);
        CHECK(cnt == 3, "NSArray count = %lu", cnt);

        /* ── 7. NSArray element access ────────────────────────── */

        typedef id (*msg_obj_ulong)(id, SEL, unsigned long);
        id elem = ((msg_obj_ulong)objc_msgSend)(array, selObjAtIdx, 1);
        int elemval = ((msg_int)objc_msgSend)(elem, selIntVal);
        CHECK(elemval == 20, "NSArray[1] = %d", elemval);

        /* ── 8. NSMutableString ───────────────────────────────── */

        id mstr = ((msg_id_void)objc_msgSend)(
            NSMutableStringClass, selString);
        CHECK(mstr != nil, "NSMutableString created");

        id part1 = ((msg_id_cstr)objc_msgSend)(
            NSStringClass, selWithUTF8, "Hello");
        id part2 = ((msg_id_cstr)objc_msgSend)(
            NSStringClass, selWithUTF8, " World");

        ((msg_void_id)objc_msgSend)(mstr, selAppend, part1);
        ((msg_void_id)objc_msgSend)(mstr, selAppend, part2);

        const char *mres = ((msg_cstr)objc_msgSend)(mstr, selUTF8);
        CHECK(mres && strcmp(mres, "Hello World") == 0,
              "NSMutableString = \"%s\"", mres ? mres : "(null)");

        /* ── 9. isEqualToString: ──────────────────────────────── */

        id expected = ((msg_id_cstr)objc_msgSend)(
            NSStringClass, selWithUTF8, "Hello World");
        typedef BOOL (*msg_bool_id)(id, SEL, id);
        BOOL eq = ((msg_bool_id)objc_msgSend)(mstr, selIsEqual, expected);
        CHECK(eq, "isEqualToString: = %d", (int)eq);

        /* ── 10. NSLog via dlsym ──────────────────────────────── */

        void (*nslog_fn)(id, ...) = dlsym(RTLD_DEFAULT, "NSLog");
        CHECK(nslog_fn != NULL, "dlsym(NSLog) = %p", (void *)nslog_fn);
        if (nslog_fn) {
            SEL selFmt = sel_registerName("stringWithFormat:");
            typedef id (*msg_fmt)(Class, SEL, id, int);
            id fmtpat = ((msg_id_cstr)objc_msgSend)(
                NSStringClass, selWithUTF8, "[objc] NSLog pid=%d");
            id fmtstr = ((msg_fmt)objc_msgSend)(
                NSStringClass, selFmt, fmtpat, getpid());
            nslog_fn(fmtstr);
        }

    } /* @autoreleasepool */

    printf("[objc] === Results: %d error(s) ===\n", errors);
    return errors;
}
