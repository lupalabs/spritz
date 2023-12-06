#ifndef _LUPA_UTIL
#define _LUPA_UTIL

#include <stdint.h>

// a lot of the stuff here was taken from https://nullprogram.com/blog/2023/10/08/

// Primitive Types
typedef uint8_t   u8;
// typedef char16_t  c16;
typedef int32_t   b32;
typedef int32_t   i32;
typedef uint32_t  u32;
typedef uint64_t  u64;
typedef float     f32;
typedef double    f64;
typedef uintptr_t uptr;
typedef unsigned char      byte;
typedef ptrdiff_t size;
typedef size_t    usize;

// standard macros
#define sizeof(x)    (size)sizeof(x)
#define alignof(x)   (size)_Alignof(x)
#define countof(a)   (sizeof(a) / sizeof(*(a)))
#define lengthof(s)  (countof(s) - 1)
#define assert(c)  while (!(c)) __builtin_unreachable()

// Structs

// string structs
#define s8(s) (s8){(u8 *)s, lengthof(s)}
typedef struct {
    u8  *data;
    size len;
} s8;

// string functions
// todo

// Result Structs. Use RESULT_STRUCT(typename) once to generate a struct. Use RESULT(typename) whereever you need the typename
#define RESULT(type) type##_RESULT
#define RESULT_STRUCT(type) typedef struct { type value; boolean ok; } RESULT(type);

#endif // _LUPA_UTIL