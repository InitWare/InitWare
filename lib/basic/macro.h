#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>

#include "bsdglibc.h"

#ifdef HAVE_sys_sysmacros_h
#include <sys/sysmacros.h>
#endif

/* Note: on GCC "no_sanitize_address" is a function attribute only, on llvm it may also be applied to global
 * variables. We define a specific macro which knows this. Note that on GCC we don't need this decorator so much, since
 * our primary use case for this attribute is registration structures placed in named ELF sections which shall not be
 * padded, but GCC doesn't pad those anyway if AddressSanitizer is enabled. */
// HACK: For now, never
// #if HAS_FEATURE_ADDRESS_SANITIZER && defined(__clang__)
#if 0
#define _variable_no_sanitize_address_ __attribute__((__no_sanitize_address__))
#else
#define _variable_no_sanitize_address_
#endif

#define _align_(x) __attribute__((__aligned__(x)))
#define _alignas_(x) __attribute__((__aligned__(alignof(x))))
#define _alignptr_ __attribute__((__aligned__(sizeof(void *))))
#define _printf_(a, b) __attribute__((format(printf, a, b)))
#define _alloc_(...) __attribute__((alloc_size(__VA_ARGS__)))
#define _sentinel_ __attribute__((sentinel))
#define _unused_ __attribute__((unused))
#define _destructor_ __attribute__((destructor))
#define _pure_ __attribute__((pure))
#define _returns_nonnull_ __attribute__((__returns_nonnull__))
#define _noinline_ __attribute__((noinline))
#define _const_ __attribute__((const))
#define _deprecated_ __attribute__((deprecated))
#define _packed_ __attribute__((packed))
#define _malloc_ __attribute__((malloc))
#define _weak_ __attribute__((weak))
#define _likely_(x) (__builtin_expect(!!(x), 1))
#define _unlikely_(x) (__builtin_expect(!!(x), 0))
#define _public_ __attribute__((visibility("default")))
#define _hidden_ __attribute__((visibility("hidden")))
#define _weakref_(x) __attribute__((weakref(#x)))
#define _cleanup_(x) __attribute__((cleanup(x)))
#define _section_(x) __attribute__((__section__(x)))
#define _used_ __attribute__((__used__))
#define _warn_unused_result_ __attribute__((__warn_unused_result__))
#define _retain_ __attribute__((__retain__))
#define _noreturn_ _Noreturn
#if __GNUC__ >= 7 || (defined(__clang__) && __clang_major__ >= 10)
#  define _fallthrough_ __attribute__((__fallthrough__))
#else
#  define _fallthrough_
#endif

// HACK: Prototypes needed here?
/* Logging for various assertions */
_noreturn_ void log_assert_failed(
                const char *text,
                const char *file,
                int line,
                const char *func);

_noreturn_ void log_assert_failed_unreachable(
                const char *file,
                int line,
                const char *func);

void log_assert_failed_return(
                const char *text,
                const char *file,
                int line,
                const char *func);

#ifndef __COVERITY__
#  define VOID_0 ((void)0)
#else
#  define VOID_0 ((void*)0)
#endif

/* Temporarily disable some warnings */
#define DISABLE_WARNING_DECLARATION_AFTER_STATEMENT                            \
	_Pragma("GCC diagnostic push");                                        \
	_Pragma("GCC diagnostic ignored \"-Wdeclaration-after-statement\"")

#define DISABLE_WARNING_FORMAT_NONLITERAL                                      \
	_Pragma("GCC diagnostic push");                                        \
	_Pragma("GCC diagnostic ignored \"-Wformat-nonliteral\"")

#define DISABLE_WARNING_MISSING_PROTOTYPES                                     \
	_Pragma("GCC diagnostic push");                                        \
	_Pragma("GCC diagnostic ignored \"-Wmissing-prototypes\"")

#define DISABLE_WARNING_NONNULL                                                \
	_Pragma("GCC diagnostic push");                                        \
	_Pragma("GCC diagnostic ignored \"-Wnonnull\"")

#define DISABLE_WARNING_SHADOW                                                 \
	_Pragma("GCC diagnostic push");                                        \
	_Pragma("GCC diagnostic ignored \"-Wshadow\"")

#define DISABLE_WARNING_INCOMPATIBLE_POINTER_TYPES                             \
	_Pragma("GCC diagnostic push");                                        \
	_Pragma("GCC diagnostic ignored \"-Wincompatible-pointer-types\"")

#define DISABLE_WARNING_ADDRESS                                         \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Waddress\"")

#define REENABLE_WARNING _Pragma("GCC diagnostic pop")

/* automake test harness */
#define EXIT_TEST_SKIP 77

/* align to next higher power-of-2 (except for: 0 => 0, overflow => 0) */
static inline unsigned long ALIGN_POWER2(unsigned long u) {

        /* Avoid subtraction overflow */
        if (u == 0)
                return 0;

        /* clz(0) is undefined */
        if (u == 1)
                return 1;

        /* left-shift overflow is undefined */
        if (__builtin_clzl(u - 1UL) < 1)
                return 0;

        return 1UL << (sizeof(u) * 8 - __builtin_clzl(u - 1UL));
}

static inline size_t GREEDY_ALLOC_ROUND_UP(size_t l) {
        size_t m;

        /* Round up allocation sizes a bit to some reasonable, likely larger value. This is supposed to be
         * used for cases which are likely called in an allocation loop of some form, i.e. that repetitively
         * grow stuff, for example strv_extend() and suchlike.
         *
         * Note the difference to GREEDY_REALLOC() here, as this helper operates on a single size value only,
         * and rounds up to next multiple of 2, needing no further counter.
         *
         * Note the benefits of direct ALIGN_POWER2() usage: type-safety for size_t, sane handling for very
         * small (i.e. <= 2) and safe handling for very large (i.e. > SSIZE_MAX) values. */

        if (l <= 2)
                return 2; /* Never allocate less than 2 of something.  */

        m = ALIGN_POWER2(l);
        if (m == 0) /* overflow? */
                return l;

        return m;
}

#define U64_KB UINT64_C(1024)
#define U64_MB (UINT64_C(1024) * U64_KB)
#define U64_GB (UINT64_C(1024) * U64_MB)

#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)

#define XCONCATENATE(x, y) x##y
#define CONCATENATE(x, y) XCONCATENATE(x, y)

#define UNIQ_T(x, uniq) CONCATENATE(__unique_prefix_, CONCATENATE(x, uniq))
#define UNIQ __COUNTER__

#define sizeof_field(struct_type, member) sizeof(((struct_type *) 0)->member)
#define endoffsetof_field(struct_type, member) (offsetof(struct_type, member) + sizeof_field(struct_type, member))

/* When func() returns the void value (NULL, -1, …) of the appropriate type */
#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func)                 \
        static inline void func##p(type *p) {                   \
                if (*p)                                         \
                        *p = func(*p);                          \
        }

/* When func() doesn't return the appropriate type, set variable to empty afterwards.
 * The func() may be provided by a dynamically loaded shared library, hence add an assertion. */
#define DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(type, func, empty)     \
        static inline void func##p(type *p) {                   \
                if (*p != (empty)) {                            \
                        DISABLE_WARNING_ADDRESS;                \
                        assert(func);                           \
                        REENABLE_WARNING;                       \
                        func(*p);                               \
                        *p = (empty);                           \
                }                                               \
        }

#define _DEFINE_TRIVIAL_REF_FUNC(type, name, scope)             \
        scope type *name##_ref(type *p) {                       \
                if (!p)                                         \
                        return NULL;                            \
                                                                \
                /* For type check. */                           \
                unsigned *q = &p->n_ref;                        \
                assert(*q > 0);                                 \
                assert_se(*q < UINT_MAX);                       \
                                                                \
                (*q)++;                                         \
                return p;                                       \
        }

#define _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, scope) \
        scope type *name##_unref(type *p) {                      \
                if (!p)                                          \
                        return NULL;                             \
                                                                 \
                assert(p->n_ref > 0);                            \
                p->n_ref--;                                      \
                if (p->n_ref > 0)                                \
                        return NULL;                             \
                                                                 \
                return free_func(p);                             \
        }

#define DEFINE_TRIVIAL_REF_FUNC(type, name)     \
        _DEFINE_TRIVIAL_REF_FUNC(type, name,)
#define DEFINE_PRIVATE_TRIVIAL_REF_FUNC(type, name)     \
        _DEFINE_TRIVIAL_REF_FUNC(type, name, static)
#define DEFINE_PUBLIC_TRIVIAL_REF_FUNC(type, name)      \
        _DEFINE_TRIVIAL_REF_FUNC(type, name, _public_)

#define DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func)        \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func,)
#define DEFINE_PRIVATE_TRIVIAL_UNREF_FUNC(type, name, free_func)        \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, static)
#define DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC(type, name, free_func)         \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, _public_)

#define DEFINE_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func);

#define DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_PRIVATE_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_PRIVATE_TRIVIAL_UNREF_FUNC(type, name, free_func);

#define DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_PUBLIC_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC(type, name, free_func);

/* Restriction/bug (see above) was fixed in GCC 15 and clang 19.*/
#if __GNUC__ >= 15 || (defined(__clang__) && __clang_major__ >= 19)
#define DECLARE_FLEX_ARRAY(type, name) type name[];
#else
/* Declare a flexible array usable in a union.
 * This is essentially a work-around for a pointless constraint in C99
 * and might go away in some future version of the standard.
 *
 * See https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=3080ea5553cc909b000d1f1d964a9041962f2c5b
 */
#define DECLARE_FLEX_ARRAY(type, name)                 \
        struct {                                       \
                dummy_t __empty__ ## name;             \
                type name[];                           \
        }
#endif

/* Returns true if the passed integer is a positive power of two */
#define CONST_ISPOWEROF2(x)                     \
        ((x) > 0 && ((x) & ((x) - 1)) == 0)

static inline uint64_t u64_multiply_safe(uint64_t a, uint64_t b) {
        if (_unlikely_(a != 0 && b > (UINT64_MAX / a)))
                return 0; /* overflow */

        return a * b;
}

/* Rounds up */

#define ALIGN4(l) (((l) + 3) & ~3)
#define ALIGN8(l) (((l) + 7) & ~7)

#ifndef ALIGN
#if __SIZEOF_POINTER__ == 8
#define ALIGN(l) ALIGN8(l)
#elif __SIZEOF_POINTER__ == 4
#define ALIGN(l) ALIGN4(l)
#else
#error "Wut? Pointers are neither 4 nor 8 bytes long?"
#endif
#endif

#define ALIGN_PTR(p) ((void *)ALIGN((unsigned long)(p)))
#define ALIGN4_PTR(p) ((void *)ALIGN4((unsigned long)(p)))
#define ALIGN8_PTR(p) ((void *)ALIGN8((unsigned long)(p)))

#define MUL_SAFE(ret, a, b) (!__builtin_mul_overflow(a, b, ret))

#define ISPOWEROF2(x)                                                  \
        __builtin_choose_expr(                                         \
                __builtin_constant_p(x),                               \
                CONST_ISPOWEROF2(x),                                   \
                ({                                                     \
                        const typeof(x) _x = (x);                      \
                        CONST_ISPOWEROF2(_x);                          \
                }))

/* Same as ALIGN_TO but callable in constant contexts. */
#define CONST_ALIGN_TO(l, ali)                                         \
        __builtin_choose_expr(                                         \
                __builtin_constant_p(l) &&                             \
                __builtin_constant_p(ali) &&                           \
                CONST_ISPOWEROF2(ali) &&                               \
                (l <= SIZE_MAX - (ali - 1)),      /* overflow? */      \
                ((l) + (ali) - 1) & ~((ali) - 1),                      \
                VOID_0)

static inline size_t ALIGN_TO(size_t l, size_t ali) {
        assert(ISPOWEROF2(ali));

        if (l > SIZE_MAX - (ali - 1))
                return SIZE_MAX; /* indicate overflow */

        return ((l + (ali - 1)) & ~(ali - 1));
}

static inline uint64_t ALIGN_TO_U64(uint64_t l, uint64_t ali) {
        assert(ISPOWEROF2(ali));

        if (l > UINT64_MAX - (ali - 1))
                return UINT64_MAX; /* indicate overflow */

        return ((l + (ali - 1)) & ~(ali - 1));
}

static inline size_t ALIGN_DOWN(size_t l, size_t ali) {
        assert(ISPOWEROF2(ali));

        return l & ~(ali - 1);
}

static inline uint64_t ALIGN_DOWN_U64(uint64_t l, uint64_t ali) {
        assert(ISPOWEROF2(ali));

        return l & ~(ali - 1);
}

static inline size_t ALIGN_OFFSET(size_t l, size_t ali) {
        assert(ISPOWEROF2(ali));

        return l & (ali - 1);
}

static inline uint64_t ALIGN_OFFSET_U64(uint64_t l, uint64_t ali) {
        assert(ISPOWEROF2(ali));

        return l & (ali - 1);
}

#define ALIGN_TO_PTR(p, ali) ((void *)ALIGN_TO((unsigned long)(p), (ali)))

#define ELEMENTSOF(x) (sizeof(x) / sizeof((x)[0]))

/*
 * STRLEN - return the length of a string literal, minus the trailing NUL byte.
 *          Contrary to strlen(), this is a constant expression.
 * @x: a string literal.
 */
#define STRLEN(x) (sizeof("" x "") - 1)

/*
 * container_of - cast a member of a structure out to the containing structure
 * @ptr: the pointer to the member.
 * @type: the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 */
#define container_of(ptr, type, member)                                        \
	__container_of(UNIQ, (ptr), type, member)
#define __container_of(uniq, ptr, type, member)                                \
	__extension__({                                                        \
		const typeof(((type *)0)->member) *UNIQ_T(A, uniq) = (ptr);    \
		(type *)((char *)UNIQ_T(A, uniq) - offsetof(type, member));    \
	})

#ifndef __MAX
#undef MAX
#define MAX(a, b) __MAX(UNIQ, (a), UNIQ, (b))
#define __MAX(aq, a, bq, b)                                                    \
	__extension__({                                                        \
		const typeof(a) UNIQ_T(A, aq) = (a);                           \
		const typeof(b) UNIQ_T(B, bq) = (b);                           \
		UNIQ_T(A, aq) > UNIQ_T(B, bq) ? UNIQ_T(A, aq) : UNIQ_T(B, bq); \
	})
#endif

/* evaluates to (void) if _A or _B are not constant or of different types */
#define CONST_MAX(_A, _B)                                                      \
	__extension__(__builtin_choose_expr(__builtin_constant_p(_A) &&        \
			__builtin_constant_p(_B) &&                            \
			__builtin_types_compatible_p(typeof(_A), typeof(_B)),  \
		((_A) > (_B)) ? (_A) : (_B), (void)0))

/* takes two types and returns the size of the larger one */
#define MAXSIZE(A, B)                                                          \
	(sizeof(union _packed_ {                                               \
		typeof(A) a;                                                   \
		typeof(B) b;                                                   \
	}))

#define MAX3(x, y, z)                                                          \
	__extension__({                                                        \
		const typeof(x) _c = MAX(x, y);                                \
		MAX(_c, z);                                                    \
	})

#ifndef __MIN
#undef MIN
#define MIN(a, b) __MIN(UNIQ, (a), UNIQ, (b))
#define __MIN(aq, a, bq, b)                                                    \
	__extension__({                                                        \
		const typeof(a) UNIQ_T(A, aq) = (a);                           \
		const typeof(b) UNIQ_T(B, bq) = (b);                           \
		UNIQ_T(A, aq) < UNIQ_T(B, bq) ? UNIQ_T(A, aq) : UNIQ_T(B, bq); \
	})
#endif

#define MIN3(x, y, z)                                                          \
	__extension__({                                                        \
		const typeof(x) _c = MIN(x, y);                                \
		MIN(_c, z);                                                    \
	})

#define LESS_BY(a, b) __LESS_BY(UNIQ, (a), UNIQ, (b))
#define __LESS_BY(aq, a, bq, b)                                                \
	__extension__({                                                        \
		const typeof(a) UNIQ_T(A, aq) = (a);                           \
		const typeof(b) UNIQ_T(B, bq) = (b);                           \
		UNIQ_T(A, aq) > UNIQ_T(B, bq) ?                                \
			      UNIQ_T(A, aq) - UNIQ_T(B, bq) :                        \
			      0;                                                     \
	})

#undef CLAMP
#define CLAMP(x, low, high) __CLAMP(UNIQ, (x), UNIQ, (low), UNIQ, (high))
#define __CLAMP(xq, x, lowq, low, highq, high)                                 \
	__extension__({                                                        \
		const typeof(x) UNIQ_T(X, xq) = (x);                           \
		const typeof(low) UNIQ_T(LOW, lowq) = (low);                   \
		const typeof(high) UNIQ_T(HIGH, highq) = (high);               \
		UNIQ_T(X, xq) > UNIQ_T(HIGH, highq) ? UNIQ_T(HIGH, highq) :    \
			UNIQ_T(X, xq) < UNIQ_T(LOW, lowq) ?                    \
							    UNIQ_T(LOW, lowq) :      \
							    UNIQ_T(X, xq);           \
	})

#define CMP(a, b) __CMP(UNIQ, (a), UNIQ, (b))
#define __CMP(aq, a, bq, b)                                                    \
	({                                                                     \
		const typeof(a) UNIQ_T(A, aq) = (a);                           \
		const typeof(b) UNIQ_T(B, bq) = (b);                           \
		UNIQ_T(A, aq)<UNIQ_T(B, bq) ? -1 : UNIQ_T(A, aq)> UNIQ_T(B,    \
			bq) ?                                                  \
			      1 :                                                    \
			      0;                                                     \
	})

/* [(x + y - 1) / y] suffers from an integer overflow, even though the
 * computation should be possible in the given type. Therefore, we use
 * [x / y + !!(x % y)]. Note that on "Real CPUs" a division returns both the
 * quotient and the remainder, so both should be equally fast. */
#define DIV_ROUND_UP(x, y) __DIV_ROUND_UP(UNIQ, (x), UNIQ, (y))
#define __DIV_ROUND_UP(xq, x, yq, y)                                    \
        ({                                                              \
                const typeof(x) UNIQ_T(X, xq) = (x);                    \
                const typeof(y) UNIQ_T(Y, yq) = (y);                    \
                (UNIQ_T(X, xq) / UNIQ_T(Y, yq) + !!(UNIQ_T(X, xq) % UNIQ_T(Y, yq))); \
        })

/* Rounds up x to the next multiple of y. Resolves to typeof(x) -1 in case of overflow */
#define __ROUND_UP(q, x, y)                                             \
        ({                                                              \
                const typeof(y) UNIQ_T(A, q) = (y);                     \
                const typeof(x) UNIQ_T(B, q) = DIV_ROUND_UP((x), UNIQ_T(A, q)); \
                typeof(x) UNIQ_T(C, q);                                 \
                MUL_SAFE(&UNIQ_T(C, q), UNIQ_T(B, q), UNIQ_T(A, q)) ? UNIQ_T(C, q) : (typeof(x)) -1; \
        })
#define ROUND_UP(x, y) __ROUND_UP(UNIQ, (x), (y))

#define assert_message_se(expr, message)                                \
        do {                                                            \
                if (_unlikely_(!(expr)))                                \
                        log_assert_failed(message, __FILE__, __LINE__, __func__); \
        } while (false)

#define assert_log(expr, message) ((_likely_(expr))                     \
        ? (true)                                                        \
        : (log_assert_failed_return(message, __FILE__, __LINE__, __func__), false))

#define assert_se(expr) assert_message_se(expr, #expr)

// #define assert_se(expr)                                                        \
// 	do {                                                                   \
// 		if (_unlikely_(!(expr)))                                       \
// 			log_assert_failed(#expr, __FILE__, __LINE__,           \
// 				__PRETTY_FUNCTION__);                          \
// 	} while (false)

/* We override the glibc assert() here. */
#undef assert
#ifdef NDEBUG
#define assert(expr) ({ if (!(expr)) __builtin_unreachable(); })
#else
#define assert(expr) assert_message_se(expr, #expr)
#endif

// #define assert_not_reached(t)                                                  \
// 	do {                                                                   \
// 		log_assert_failed_unreachable(t, __FILE__, __LINE__,           \
// 			__PRETTY_FUNCTION__);                                  \
// 	} while (false)
#define assert_not_reached()                                            \
        log_assert_failed_unreachable(__FILE__, __LINE__, __func__)

#define ASSERT_PTR(expr) _ASSERT_PTR(expr, UNIQ_T(_expr_, UNIQ), assert)
#define ASSERT_SE_PTR(expr) _ASSERT_PTR(expr, UNIQ_T(_expr_, UNIQ), assert_se)
#define _ASSERT_PTR(expr, var, check)      \
        ({                                 \
                typeof(expr) var = (expr); \
                check(var);                \
                var;                       \
        })

#if defined(static_assert)
/* static_assert() is sometimes defined in a way that trips up
 * -Wdeclaration-after-statement, hence let's temporarily turn off
 * this warning around it. */
#define assert_cc(expr)                                                        \
	DISABLE_WARNING_DECLARATION_AFTER_STATEMENT;                           \
	static_assert(expr, #expr);                                            \
	REENABLE_WARNING
#else
#define assert_cc(expr)                                                        \
	DISABLE_WARNING_DECLARATION_AFTER_STATEMENT;                           \
	struct CONCATENATE(_assert_struct_, __COUNTER__) {                     \
		char x[(expr) ? 0 : -1];                                       \
	};                                                                     \
	REENABLE_WARNING
#endif

#define assert_return(expr, r)                                          \
        do {                                                            \
                if (!assert_log(expr, #expr))                           \
                        return (r);                                     \
        } while (false)

/* A macro to force copying of a variable from memory. This is useful whenever we want to read something from
 * memory and want to make sure the compiler won't optimize away the destination variable for us. It's not
 * supposed to be a full CPU memory barrier, i.e. CPU is still allowed to reorder the reads, but it is not
 * allowed to remove our local copies of the variables. We want this to work for unaligned memory, hence
 * memcpy() is great for our purposes. */
#define READ_NOW(x)                                                     \
        ({                                                              \
                typeof(x) _copy;                                        \
                memcpy(&_copy, &(x), sizeof(_copy));                    \
                asm volatile ("" : : : "memory");                       \
                _copy;                                                  \
        })

typedef struct {
        int _empty[0];
} dummy_t;

assert_cc(sizeof(dummy_t) == 0);

/* A little helper for subtracting 1 off a pointer in a safe UB-free way. This is intended to be used for
 * loops that count down from a high pointer until some base. A naive loop would implement this like this:
 *
 * for (p = end-1; p >= base; p--) …
 *
 * But this is not safe because p before the base is UB in C. With this macro the loop becomes this instead:
 *
 * for (p = PTR_SUB1(end, base); p; p = PTR_SUB1(p, base)) …
 *
 * And is free from UB! */
#define PTR_SUB1(p, base)                                \
        ({                                               \
                typeof(p) _q = (p);                      \
                _q && _q > (base) ? &_q[-1] : NULL;      \
        })

#define PTR_TO_PID(p) ((pid_t)((intptr_t)(p)))
#define PID_TO_PTR(u) ((void *)((intptr_t)(u)))

#define PTR_TO_INT(p) ((int)((intptr_t)(p)))
#define INT_TO_PTR(u) ((void *)((intptr_t)(u)))
#define PTR_TO_UINT(p) ((unsigned int)((uintptr_t)(p)))
#define UINT_TO_PTR(u) ((void *)((uintptr_t)(u)))

#define PTR_TO_LONG(p) ((long)((intptr_t)(p)))
#define LONG_TO_PTR(u) ((void *)((intptr_t)(u)))
#define PTR_TO_ULONG(p) ((unsigned long)((uintptr_t)(p)))
#define ULONG_TO_PTR(u) ((void *)((uintptr_t)(u)))

#define PTR_TO_INT32(p) ((int32_t)((intptr_t)(p)))
#define INT32_TO_PTR(u) ((void *)((intptr_t)(u)))
#define PTR_TO_UINT32(p) ((uint32_t)((uintptr_t)(p)))
#define UINT32_TO_PTR(u) ((void *)((uintptr_t)(u)))

#define PTR_TO_INT64(p) ((int64_t)((intptr_t)(p)))
#define INT64_TO_PTR(u) ((void *)((intptr_t)(u)))
#define PTR_TO_UINT64(p) ((uint64_t)((uintptr_t)(p)))
#define UINT64_TO_PTR(u) ((void *)((uintptr_t)(u)))

#define PTR_TO_SIZE(p) ((size_t)((uintptr_t)(p)))
#define SIZE_TO_PTR(u) ((void *)((uintptr_t)(u)))

/* The following macros add 1 when converting things, since UID 0 is a
 * valid UID, while the pointer NULL is special */
#define PTR_TO_UID(p) ((uid_t)(((uintptr_t)(p)) - 1))
#define UID_TO_PTR(u) ((void *)(((uintptr_t)(u)) + 1))

#define PTR_TO_GID(p) ((gid_t)(((uintptr_t)(p)) - 1))
#define GID_TO_PTR(u) ((void *)(((uintptr_t)(u)) + 1))

#define zero(x) (memzero(&(x), sizeof(x)))

#define CHAR_TO_STR(x) ((char[2]){ x, 0 })

#define char_array_0(x) x[sizeof(x) - 1] = 0;

#define IOVEC_SET_STRING(i, s)                                                 \
	do {                                                                   \
		struct iovec *_i = &(i);                                       \
		char *_s = (char *)(s);                                        \
		_i->iov_base = _s;                                             \
		_i->iov_len = strlen(_s);                                      \
	} while (false)

static inline size_t
IOVEC_TOTAL_SIZE(const struct iovec *i, unsigned n)
{
	unsigned j;
	size_t r = 0;

	for (j = 0; j < n; j++)
		r += i[j].iov_len;

	return r;
}

static inline size_t
IOVEC_INCREMENT(struct iovec *i, unsigned n, size_t k)
{
	unsigned j;

	for (j = 0; j < n; j++) {
		size_t sub;

		if (_unlikely_(k <= 0))
			break;

		sub = MIN(i[j].iov_len, k);
		i[j].iov_len -= sub;
		i[j].iov_base = (uint8_t *)i[j].iov_base + sub;
		k -= sub;
	}

	return k;
}

#define VA_FORMAT_ADVANCE(format, ap)                                          \
	do {                                                                   \
		int _argtypes[128];                                            \
		size_t _i, _k;                                                 \
		_k = parse_printf_format((format), ELEMENTSOF(_argtypes),      \
			_argtypes);                                            \
		assert(_k < ELEMENTSOF(_argtypes));                            \
		for (_i = 0; _i < _k; _i++) {                                  \
			if (_argtypes[_i] & PA_FLAG_PTR) {                     \
				(void)va_arg(ap, void *);                      \
				continue;                                      \
			}                                                      \
                                                                               \
			switch (_argtypes[_i]) {                               \
			case PA_INT:                                           \
			case PA_INT | PA_FLAG_SHORT:                           \
			case PA_CHAR:                                          \
				(void)va_arg(ap, int);                         \
				break;                                         \
			case PA_INT | PA_FLAG_LONG:                            \
				(void)va_arg(ap, long int);                    \
				break;                                         \
			case PA_INT | PA_FLAG_LONG_LONG:                       \
				(void)va_arg(ap, long long int);               \
				break;                                         \
			case PA_WCHAR:                                         \
				(void)va_arg(ap, wchar_t);                     \
				break;                                         \
			case PA_WSTRING:                                       \
			case PA_STRING:                                        \
			case PA_POINTER:                                       \
				(void)va_arg(ap, void *);                      \
				break;                                         \
			case PA_FLOAT:                                         \
			case PA_DOUBLE:                                        \
				(void)va_arg(ap, double);                      \
				break;                                         \
			case PA_DOUBLE | PA_FLAG_LONG_DOUBLE:                  \
				(void)va_arg(ap, long double);                 \
				break;                                         \
			default:                                               \
				assert_not_reached();												    \
			}                                                      \
		}                                                              \
	} while (false)

/* Returns the number of chars needed to format variables of the
 * specified type as a decimal string. Adds in extra space for a
 * negative '-' prefix (hence works correctly on signed
 * types). Includes space for the trailing NUL. */
#define DECIMAL_STR_MAX(type)                                                  \
	(2 +                                                                   \
		(sizeof(type) <= 1 ? 3 :                                       \
				sizeof(type) <= 2 ?                            \
					   5 :                                       \
				sizeof(type) <= 4 ?                            \
					   10 :                                      \
				sizeof(type) <= 8 ?                            \
					   20 :                                      \
					   sizeof(int[-2 * (sizeof(type) > 8)])))

#define SET_FLAG(v, flag, b) (v) = (b) ? ((v) | (flag)) : ((v) & ~(flag))
#define FLAGS_SET(v, flags) ((~(v) & (flags)) == 0)

/* Takes inspiration from Rust's Option::take() method: reads and returns a pointer, but at the same time
 * resets it to NULL. See: https://doc.rust-lang.org/std/option/enum.Option.html#method.take */
#define TAKE_GENERIC(var, type, nullvalue)                       \
        ({                                                       \
                type *_pvar_ = &(var);                           \
                type _var_ = *_pvar_;                            \
                type _nullvalue_ = nullvalue;                    \
                *_pvar_ = _nullvalue_;                           \
                _var_;                                           \
        })
#define TAKE_PTR_TYPE(ptr, type) TAKE_GENERIC(ptr, type, NULL)
#define TAKE_PTR(ptr) TAKE_PTR_TYPE(ptr, typeof(ptr))
#define TAKE_STRUCT_TYPE(s, type) TAKE_GENERIC(s, type, {})
#define TAKE_STRUCT(s) TAKE_STRUCT_TYPE(s, typeof(s))

#define IN_SET(x, y, ...)                                                      \
	({                                                                     \
		const typeof(y) _y = (y);                                      \
		const typeof(_y) _x = (x);                                     \
		unsigned _i;                                                   \
		bool _found = false;                                           \
		for (_i = 0; _i < 1 +                                          \
				sizeof((const typeof(_x)[]){ __VA_ARGS__ }) /  \
					sizeof(const typeof(_x));              \
			_i++)                                                  \
			if (((const typeof(_x)[]){ _y, __VA_ARGS__ })[_i] ==   \
				_x) {                                          \
				_found = true;                                 \
				break;                                         \
			}                                                      \
		_found;                                                        \
	})

/* Return a nulstr for a standard cascade of configuration directories,
 * suitable to pass to conf_files_list_nulstr or config_parse_many. */
#define CONF_DIRS_NULSTR(n)                                                    \
	"/etc/" n ".d\0"                                                       \
	"/run/" n ".d\0"                                                       \
	"/usr/local/lib/" n ".d\0"                                             \
	"/usr/lib/" n ".d\0" CONF_DIR_SPLIT_USR(n) CONF_DIR_PREFIX(n)

#ifdef HAVE_SPLIT_USR
#define CONF_DIR_SPLIT_USR(n) "/lib/" n ".d\0"
#else
#define CONF_DIR_SPLIT_USR(n)
#endif

/* avoid repeating */
#if defined(SVC_PREFIX_IS_ROOT) || defined(SVC_PREFIX_IS_USR) ||               \
	defined(SVC_PREFIX_IS_USRLOCAL)
#define CONF_DIR_PREFIX(n)
#else
#define CONF_DIR_PREFIX(n) SVC_PREFIX "/lib/" n ".d\0"
#endif

/* Define C11 thread_local attribute even on older gcc compiler
 * version */
#ifndef thread_local
/*
 * Don't break on glibc < 2.16 that doesn't define __STDC_NO_THREADS__
 * see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=53769
 */
#if __STDC_VERSION__ >= 201112L &&                                             \
	!(defined(__STDC_NO_THREADS__) ||                                      \
		(defined(__GNU_LIBRARY__) && __GLIBC__ == 2 &&                 \
			__GLIBC_MINOR__ < 16))
#define thread_local _Thread_local
#else
#define thread_local __thread
#endif
#endif

/* Define C11 noreturn without <stdnoreturn.h> and even on older gcc
 * compiler versions */
#ifndef noreturn
#if __STDC_VERSION__ >= 201112L
#define noreturn _Noreturn
#else
#define noreturn __attribute__((noreturn))
#endif
#endif

#define UID_INVALID ((uid_t)-1)
#define GID_INVALID ((gid_t)-1)
#define MODE_INVALID ((mode_t)-1)

	static inline bool
	UID_IS_INVALID(uid_t uid)
{
	/* We consider both the old 16bit -1 user and the newer 32bit
         * -1 user invalid, since they are or used to be incompatible
         * with syscalls such as setresuid() or chown(). */

	return uid == (uid_t)((uint32_t)-1) || uid == (uid_t)((uint16_t)-1);
}

static inline bool
GID_IS_INVALID(gid_t gid)
{
	return gid == (gid_t)((uint32_t)-1) || gid == (gid_t)((uint16_t)-1);
}

#define CMSG_FOREACH(cmsg, mh)                                                 \
	for ((cmsg) = CMSG_FIRSTHDR(mh); (cmsg);                               \
		(cmsg) = CMSG_NXTHDR((mh), (cmsg)))

#define unimplemented() log_debug("%s: unimplemented\n", __FUNCTION__)
#define unimplemented_msg(...)                                                 \
	log_debug("%s: %s: unimplemented\n", __FUNCTION__, __VA_ARGS__)

#define STRV_MAKE(...) ((char**) ((const char*[]) { __VA_ARGS__, NULL }))
#define STRV_MAKE_EMPTY ((char*[1]) { NULL })
#define STRV_MAKE_CONST(...) ((const char* const*) ((const char*[]) { __VA_ARGS__, NULL }))

/* Pointers range from NULL to POINTER_MAX */
#define POINTER_MAX ((void*) UINTPTR_MAX)

#define _FOREACH_ARRAY(i, array, num, m, end)                           \
        for (typeof(array[0]) *i = (array), *end = ({                   \
                                typeof(num) m = (num);                  \
                                (i && m > 0) ? i + m : NULL;            \
                        }); end && i < end; i++)

#define FOREACH_ARRAY(i, array, num)                                    \
        _FOREACH_ARRAY(i, array, num, UNIQ_T(m, UNIQ), UNIQ_T(end, UNIQ))

#include "log.h"
