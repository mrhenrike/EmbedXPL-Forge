/*
 * testexec_objc_class.m — Test real ObjC class definitions in libload
 *
 * Unlike testexec_objc.m (which only *consumes* Foundation classes
 * via the raw C API), this test DEFINES its own ObjC classes with
 * @interface/@implementation.  This requires the reflective loader
 * to register loaded ObjC metadata with the runtime.
 *
 * Tests:
 *   1. Custom class with methods and properties
 *   2. Inheritance (subclass of custom class)
 *   3. Protocol conformance
 *   4. Category on custom class
 *   5. +load method invocation
 *   6. @property synthesis (getter/setter)
 *   7. NSObject integration (respondsToSelector:, class methods)
 *
 * Requires Foundation (loaded via dlopen).
 * Returns 0 on success, or the number of failed tests.
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include <objc/runtime.h>
#include <objc/message.h>
#include <objc/NSObject.h>

/* ── Helpers ───────────────────────────────────────────────────── */

static int errors;
static int load_called = 0;

#define CHECK(cond, fmt, ...)                                       \
    do {                                                            \
        if (cond) {                                                 \
            printf("[objc-class] PASS: " fmt "\n", ##__VA_ARGS__);  \
        } else {                                                    \
            printf("[objc-class] FAIL: " fmt "\n", ##__VA_ARGS__);  \
            errors++;                                               \
        }                                                           \
    } while (0)

/* ── Protocol ──────────────────────────────────────────────────── */

@protocol LLGreeter
- (const char *)greeting;
@end

/* ── Base class ────────────────────────────────────────────────── */

@interface LLTestObject : NSObject <LLGreeter> {
    int _value;
}
@property (nonatomic, assign) int value;
- (int)doubleValue;
+ (const char *)className;
@end

@implementation LLTestObject

+ (void)load
{
    load_called = 1;
}

- (instancetype)initWithValue:(int)v
{
    self = [super init];
    if (self)
        _value = v;
    return self;
}

- (int)doubleValue
{
    return _value * 2;
}

+ (const char *)className
{
    return "LLTestObject";
}

- (const char *)greeting
{
    return "Hello from LLTestObject";
}

@end

/* ── Subclass ──────────────────────────────────────────────────── */

@interface LLSubObject : LLTestObject
- (int)tripleValue;
@end

@implementation LLSubObject

- (int)tripleValue
{
    return self.value * 3;
}

- (const char *)greeting
{
    return "Hello from LLSubObject";
}

@end

/* ── Category ──────────────────────────────────────────────────── */

@interface LLTestObject (Extra)
- (int)squaredValue;
@end

@implementation LLTestObject (Extra)

- (int)squaredValue
{
    return _value * _value;
}

@end

/* ── main ──────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    errors = 0;

    printf("[objc-class] === ObjC class definition tests ===\n");
    printf("[objc-class] argc=%d\n", argc);

    /* Load Foundation for NSObject */
    void *fw = dlopen(
        "/System/Library/Frameworks/Foundation.framework/Foundation",
        RTLD_NOW);
    CHECK(fw != NULL, "dlopen Foundation = %p", fw);
    if (!fw) return 1;

    @autoreleasepool {

        /* 1. +load called */
        CHECK(load_called, "+load was called (load_called=%d)", load_called);

        /* 2. Class lookup via runtime */
        Class cls = objc_getClass("LLTestObject");
        CHECK(cls != Nil, "objc_getClass(LLTestObject) = %p", (void *)cls);

        /* 3. Alloc + init + method call */
        LLTestObject *obj = [[LLTestObject alloc] initWithValue:21];
        CHECK(obj != nil, "alloc+initWithValue: = %p", (void *)obj);

        int dv = [obj doubleValue];
        CHECK(dv == 42, "doubleValue = %d", dv);

        /* 4. Class method */
        const char *cn = [LLTestObject className];
        CHECK(cn && strcmp(cn, "LLTestObject") == 0,
              "+className = \"%s\"", cn ? cn : "(null)");

        /* 5. Property (synthesized getter/setter) */
        obj.value = 7;
        CHECK(obj.value == 7, "property value = %d", obj.value);
        CHECK([obj doubleValue] == 14, "doubleValue after set = %d",
              [obj doubleValue]);

        /* 6. Protocol conformance */
        const char *g = [obj greeting];
        CHECK(g && strcmp(g, "Hello from LLTestObject") == 0,
              "greeting = \"%s\"", g ? g : "(null)");

        BOOL conforms = [LLTestObject conformsToProtocol:@protocol(LLGreeter)];
        CHECK(conforms, "conformsToProtocol:LLGreeter = %d", (int)conforms);

        /* 7. Category method */
        int sq = [obj squaredValue];
        CHECK(sq == 49, "squaredValue = %d (7^2)", sq);

        /* 8. Subclass */
        LLSubObject *sub = [[LLSubObject alloc] initWithValue:5];
        CHECK(sub != nil, "LLSubObject alloc = %p", (void *)sub);

        CHECK([sub doubleValue] == 10, "sub doubleValue = %d",
              [sub doubleValue]);
        CHECK([sub tripleValue] == 15, "sub tripleValue = %d",
              [sub tripleValue]);

        const char *sg = [sub greeting];
        CHECK(sg && strcmp(sg, "Hello from LLSubObject") == 0,
              "sub greeting = \"%s\"", sg ? sg : "(null)");

        /* 9. Inheritance: responds to superclass methods */
        BOOL resp = [sub respondsToSelector:@selector(squaredValue)];
        CHECK(resp, "sub respondsToSelector:squaredValue = %d", (int)resp);

        sub.value = 4;
        CHECK([sub squaredValue] == 16, "sub squaredValue = %d (4^2)",
              [sub squaredValue]);

        /* 10. isKindOfClass: hierarchy */
        CHECK([sub isKindOfClass:[LLTestObject class]],
              "sub isKindOfClass:LLTestObject");
        CHECK([sub isKindOfClass:[NSObject class]],
              "sub isKindOfClass:NSObject");

    } /* @autoreleasepool */

    printf("[objc-class] === Results: %d error(s) ===\n", errors);
    return errors;
}
