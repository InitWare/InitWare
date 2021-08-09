/* Copyright (c) 2012 Josh Triplett <josh@joshtriplett.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef SPARSE_ENDIAN_H
#define SPARSE_ENDIAN_H

#include "compat.h"

#ifdef Have_sys_endian_h
#include <sys/endian.h>
#endif
#ifdef Have_endian_h
#include <endian.h>
#endif
#include <stdint.h>

#ifndef __bitwise
#define __bitwise
#endif

typedef uint16_t __bitwise le16_t;
typedef uint16_t __bitwise be16_t;
typedef uint32_t __bitwise le32_t;
typedef uint32_t __bitwise be32_t;
typedef uint64_t __bitwise le64_t;
typedef uint64_t __bitwise be64_t;

#endif /* SPARSE_ENDIAN_H */
