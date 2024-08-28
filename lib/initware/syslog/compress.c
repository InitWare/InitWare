/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_XZ
#include <lzma.h>
#endif

#ifdef HAVE_LZ4
#include <lz4.h>
#endif

#include "compress.h"
#include "journal-def.h"
#include "macro.h"
#include "sparse-endian.h"
#include "string-table.h"
#include "util.h"

#define ALIGN_8(l) ALIGN_TO(l, sizeof(size_t))

static const char *const object_compressed_table[_OBJECT_COMPRESSED_MASK] = {
	[OBJECT_COMPRESSED_XZ] = "XZ",
	[OBJECT_COMPRESSED_LZ4] = "LZ4",
};

static const char* const compression_table[_COMPRESSION_MAX] = {
        [COMPRESSION_NONE] = "NONE",
        [COMPRESSION_XZ]   = "XZ",
        [COMPRESSION_LZ4]  = "LZ4",
};

DEFINE_STRING_TABLE_LOOKUP(compression, Compression);

DEFINE_STRING_TABLE_LOOKUP(object_compressed, int);

int
compress_blob_xz(const void *src, uint64_t src_size, void *dst,
	size_t *dst_size)
{
#ifdef HAVE_XZ
	static const lzma_options_lzma opt = { 1u << 20u, NULL, 0,
		LZMA_LC_DEFAULT, LZMA_LP_DEFAULT, LZMA_PB_DEFAULT,
		LZMA_MODE_FAST, 128, LZMA_MF_HC3, 4 };
	static const lzma_filter filters[] = {
		{ LZMA_FILTER_LZMA2, (lzma_options_lzma *)&opt },
		{ LZMA_VLI_UNKNOWN, NULL }
	};
	lzma_ret ret;
	size_t out_pos = 0;

	assert(src);
	assert(src_size > 0);
	assert(dst);
	assert(dst_size);

	/* Returns < 0 if we couldn't compress the data or the
         * compressed result is longer than the original */

	if (src_size < 80)
		return -ENOBUFS;

	ret = lzma_stream_buffer_encode((lzma_filter *)filters, LZMA_CHECK_NONE,
		NULL, src, src_size, dst, &out_pos, src_size - 1);
	if (ret != LZMA_OK)
		return -ENOBUFS;

	*dst_size = out_pos;
	return 0;
#else
	return -EPROTONOSUPPORT;
#endif
}

int
compress_blob_lz4(const void *src, uint64_t src_size, void *dst,
	size_t *dst_size)
{
#ifdef HAVE_LZ4
	int r;

	assert(src);
	assert(src_size > 0);
	assert(dst);
	assert(dst_size);

	/* Returns < 0 if we couldn't compress the data or the
         * compressed result is longer than the original */

	if (src_size < 9)
		return -ENOBUFS;

#if LZ4_VERSION_NUMBER >= 10700
	r = LZ4_compress_default(src, (char *)dst + 8, src_size,
		src_size - 8 - 1);
#else
	r = LZ4_compress_limitedOutput(src, (char *)dst + 8, src_size,
		src_size - 8 - 1);
#endif

	if (r <= 0)
		return -ENOBUFS;

	*(le64_t *)dst = htole64(src_size);
	*dst_size = r + 8;

	return 0;
#else
	return -EPROTONOSUPPORT;
#endif
}

int decompress_blob_xz(
                const void *src,
                uint64_t src_size,
                void **dst,
                size_t* dst_size,
                size_t dst_max) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_size);

#ifdef HAVE_XZ
        _cleanup_(lzma_end_wrapper) lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;
        size_t space;
        int r;

        r = dlopen_lzma();
        if (r < 0)
                return r;

        ret = sym_lzma_stream_decoder(&s, UINT64_MAX, 0);
        if (ret != LZMA_OK)
                return -ENOMEM;

        space = MIN(src_size * 2, dst_max ?: SIZE_MAX);
        if (!greedy_realloc(dst, space, 1))
                return -ENOMEM;

        s.next_in = src;
        s.avail_in = src_size;

        s.next_out = *dst;
        s.avail_out = space;

        for (;;) {
                size_t used;

                ret = sym_lzma_code(&s, LZMA_FINISH);

                if (ret == LZMA_STREAM_END)
                        break;
                else if (ret != LZMA_OK)
                        return -ENOMEM;

                if (dst_max > 0 && (space - s.avail_out) >= dst_max)
                        break;
                else if (dst_max > 0 && space == dst_max)
                        return -ENOBUFS;

                used = space - s.avail_out;
                space = MIN(2 * space, dst_max ?: SIZE_MAX);
                if (!greedy_realloc(dst, space, 1))
                        return -ENOMEM;

                s.avail_out = space - used;
                s.next_out = *(uint8_t**)dst + used;
        }

        *dst_size = space - s.avail_out;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

int decompress_blob_lz4(
                const void *src,
                uint64_t src_size,
                void **dst,
                size_t* dst_size,
                size_t dst_max) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_size);

#ifdef HAVE_LZ4
        char* out;
        int r, size; /* LZ4 uses int for size */

        r = dlopen_lz4();
        if (r < 0)
                return r;

        if (src_size <= 8)
                return -EBADMSG;

        size = unaligned_read_le64(src);
        if (size < 0 || (unsigned) size != unaligned_read_le64(src))
                return -EFBIG;
        out = greedy_realloc(dst, size, 1);
        if (!out)
                return -ENOMEM;

        r = sym_LZ4_decompress_safe((char*)src + 8, out, src_size - 8, size);
        if (r < 0 || r != size)
                return -EBADMSG;

        *dst_size = size;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

int decompress_blob(
                Compression compression,
                const void *src,
                uint64_t src_size,
                void **dst,
                size_t* dst_size,
                size_t dst_max) {

        if (compression == COMPRESSION_XZ)
                return decompress_blob_xz(
                                src, src_size,
                                dst, dst_size, dst_max);
        else if (compression == COMPRESSION_LZ4)
                return decompress_blob_lz4(
                                src, src_size,
                                dst, dst_size, dst_max);
        // else if (compression == COMPRESSION_ZSTD)
        //         return decompress_blob_zstd(
        //                         src, src_size,
        //                         dst, dst_size, dst_max);
        else
                return -EPROTONOSUPPORT;
}

int
decompress_startswith_xz(const void *src, uint64_t src_size, void **buffer,
	size_t *buffer_size, const void *prefix, size_t prefix_len,
	uint8_t extra)
{
#ifdef HAVE_XZ
	_cleanup_(lzma_end) lzma_stream s = LZMA_STREAM_INIT;
	lzma_ret ret;

	/* Checks whether the decompressed blob starts with the
         * mentioned prefix. The byte extra needs to follow the
         * prefix */

	assert(src);
	assert(src_size > 0);
	assert(buffer);
	assert(buffer_size);
	assert(prefix);
	assert(*buffer_size == 0 || *buffer);

	ret = lzma_stream_decoder(&s, UINT64_MAX, 0);
	if (ret != LZMA_OK)
		return -EBADMSG;

	if (!(greedy_realloc(buffer, buffer_size, ALIGN_8(prefix_len + 1), 1)))
		return -ENOMEM;

	s.next_in = src;
	s.avail_in = src_size;

	s.next_out = *buffer;
	s.avail_out = *buffer_size;

	for (;;) {
		ret = lzma_code(&s, LZMA_FINISH);

		if (ret != LZMA_STREAM_END && ret != LZMA_OK)
			return -EBADMSG;

		if (*buffer_size - s.avail_out >= prefix_len + 1)
			return memcmp(*buffer, prefix, prefix_len) == 0 &&
				((const uint8_t *)*buffer)[prefix_len] == extra;

		if (ret == LZMA_STREAM_END)
			return 0;

		s.avail_out += *buffer_size;

		if (!(greedy_realloc(buffer, buffer_size, *buffer_size * 2, 1)))
			return -ENOMEM;

		s.next_out = *buffer + *buffer_size - s.avail_out;
	}

#else
	return -EPROTONOSUPPORT;
#endif
}

int
decompress_startswith_lz4(const void *src, uint64_t src_size, void **buffer,
	size_t *buffer_size, const void *prefix, size_t prefix_len,
	uint8_t extra)
{
#ifdef HAVE_LZ4
	/* Checks whether the decompressed blob starts with the
         * mentioned prefix. The byte extra needs to follow the
         * prefix */

	int r;

	assert(src);
	assert(src_size > 0);
	assert(buffer);
	assert(buffer_size);
	assert(prefix);
	assert(*buffer_size == 0 || *buffer);

	if (src_size <= 8)
		return -EBADMSG;

	if (!(greedy_realloc(buffer, buffer_size, ALIGN_8(prefix_len + 1), 1)))
		return -ENOMEM;

	r = LZ4_decompress_safe_partial(src + 8, *buffer, src_size - 8,
		prefix_len + 1, *buffer_size);

	if (r < 0)
		return -EBADMSG;
	if ((unsigned)r >= prefix_len + 1)
		return memcmp(*buffer, prefix, prefix_len) == 0 &&
			((const uint8_t *)*buffer)[prefix_len] == extra;
	else
		return 0;

#else
	return -EPROTONOSUPPORT;
#endif
}

int
decompress_startswith(int compression, const void *src, uint64_t src_size,
	void **buffer, size_t *buffer_size, const void *prefix,
	size_t prefix_len, uint8_t extra)
{
	if (compression == OBJECT_COMPRESSED_XZ)
		return decompress_startswith_xz(src, src_size, buffer,
			buffer_size, prefix, prefix_len, extra);
	else if (compression == OBJECT_COMPRESSED_LZ4)
		return decompress_startswith_lz4(src, src_size, buffer,
			buffer_size, prefix, prefix_len, extra);
	else
		return -EBADMSG;
}

int
compress_stream_xz(int fdf, int fdt, off_t max_bytes)
{
#ifdef HAVE_XZ
	_cleanup_(lzma_end) lzma_stream s = LZMA_STREAM_INIT;
	lzma_ret ret;

	uint8_t buf[BUFSIZ], out[BUFSIZ];
	lzma_action action = LZMA_RUN;

	assert(fdf >= 0);
	assert(fdt >= 0);

	ret = lzma_easy_encoder(&s, LZMA_PRESET_DEFAULT, LZMA_CHECK_CRC64);
	if (ret != LZMA_OK) {
		log_error("Failed to initialize XZ encoder: code %u", ret);
		return -EINVAL;
	}

	for (;;) {
		if (s.avail_in == 0 && action == LZMA_RUN) {
			size_t m = sizeof(buf);
			ssize_t n;

			if (max_bytes != -1 && m > (size_t)max_bytes)
				m = max_bytes;

			n = read(fdf, buf, m);
			if (n < 0)
				return -errno;
			if (n == 0)
				action = LZMA_FINISH;
			else {
				s.next_in = buf;
				s.avail_in = n;

				if (max_bytes != -1) {
					assert(max_bytes >= n);
					max_bytes -= n;
				}
			}
		}

		if (s.avail_out == 0) {
			s.next_out = out;
			s.avail_out = sizeof(out);
		}

		ret = lzma_code(&s, action);
		if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
			log_error("Compression failed: code %u", ret);
			return -EBADMSG;
		}

		if (s.avail_out == 0 || ret == LZMA_STREAM_END) {
			ssize_t n, k;

			n = sizeof(out) - s.avail_out;

			k = loop_write(fdt, out, n, false);
			if (k < 0)
				return k;

			if (ret == LZMA_STREAM_END) {
				log_debug("XZ compression finished (%" PRIu64
					  " -> %" PRIu64 " bytes, %.1f%%)",
					s.total_in, s.total_out,
					(double)s.total_out / s.total_in * 100);

				return 0;
			}
		}
	}
#else
	return -EPROTONOSUPPORT;
#endif
}

#define LZ4_BUFSIZE (512 * 1024)

int
compress_stream_lz4(int fdf, int fdt, off_t max_bytes)
{
#ifdef HAVE_LZ4

	_cleanup_free_ char *buf1 = NULL, *buf2 = NULL, *out = NULL;
	char *buf;
	LZ4_stream_t lz4_data = {};
	le32_t header;
	size_t total_in = 0, total_out = sizeof(header);
	ssize_t n;

	assert(fdf >= 0);
	assert(fdt >= 0);

	buf1 = malloc(LZ4_BUFSIZE);
	buf2 = malloc(LZ4_BUFSIZE);
	out = malloc(LZ4_COMPRESSBOUND(LZ4_BUFSIZE));
	if (!buf1 || !buf2 || !out)
		return log_oom();

	buf = buf1;
	for (;;) {
		size_t m;
		int r;

		m = LZ4_BUFSIZE;
		if (max_bytes != -1 && m > (size_t)max_bytes - total_in)
			m = max_bytes - total_in;

		n = read(fdf, buf, m);
		if (n < 0)
			return -errno;
		if (n == 0)
			break;

		total_in += n;

		r = LZ4_compress_fast_continue(&lz4_data, buf, out, n,
			LZ4_COMPRESSBOUND(LZ4_BUFSIZE), 0);
		if (r == 0) {
			log_error("LZ4 compression failed.");
			return -EBADMSG;
		}

		header = htole32(r);
		errno = 0;

		n = write(fdt, &header, sizeof(header));
		if (n < 0)
			return -errno;
		if (n != sizeof(header))
			return errno ? -errno : -EIO;

		n = loop_write(fdt, out, r, false);
		if (n < 0)
			return n;

		total_out += sizeof(header) + r;

		buf = buf == buf1 ? buf2 : buf1;
	}

	header = htole32(0);
	n = write(fdt, &header, sizeof(header));
	if (n < 0)
		return -errno;
	if (n != sizeof(header))
		return errno ? -errno : -EIO;

	log_debug("LZ4 compression finished (%zu -> %zu bytes, %.1f%%)",
		total_in, total_out, (double)total_out / total_in * 100);

	return 0;
#else
	return -EPROTONOSUPPORT;
#endif
}

int
decompress_stream_xz(int fdf, int fdt, off_t max_bytes)
{
#ifdef HAVE_XZ
	_cleanup_(lzma_end) lzma_stream s = LZMA_STREAM_INIT;
	lzma_ret ret;

	uint8_t buf[BUFSIZ], out[BUFSIZ];
	lzma_action action = LZMA_RUN;

	assert(fdf >= 0);
	assert(fdt >= 0);

	ret = lzma_stream_decoder(&s, UINT64_MAX, 0);
	if (ret != LZMA_OK) {
		log_error("Failed to initialize XZ decoder: code %u", ret);
		return -ENOMEM;
	}

	for (;;) {
		if (s.avail_in == 0 && action == LZMA_RUN) {
			ssize_t n;

			n = read(fdf, buf, sizeof(buf));
			if (n < 0)
				return -errno;
			if (n == 0)
				action = LZMA_FINISH;
			else {
				s.next_in = buf;
				s.avail_in = n;
			}
		}

		if (s.avail_out == 0) {
			s.next_out = out;
			s.avail_out = sizeof(out);
		}

		ret = lzma_code(&s, action);
		if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
			log_error("Decompression failed: code %u", ret);
			return -EBADMSG;
		}

		if (s.avail_out == 0 || ret == LZMA_STREAM_END) {
			ssize_t n, k;

			n = sizeof(out) - s.avail_out;

			if (max_bytes != -1) {
				if (max_bytes < n)
					return -EFBIG;

				max_bytes -= n;
			}

			k = loop_write(fdt, out, n, false);
			if (k < 0)
				return k;

			if (ret == LZMA_STREAM_END) {
				log_debug("XZ decompression finished (%" PRIu64
					  " -> %" PRIu64 " bytes, %.1f%%)",
					s.total_in, s.total_out,
					(double)s.total_out / s.total_in * 100);

				return 0;
			}
		}
	}
#else
	log_error("Cannot decompress file. Compiled without XZ support.");
	return -EPROTONOSUPPORT;
#endif
}

int
decompress_stream_lz4(int fdf, int fdt, off_t max_bytes)
{
#ifdef HAVE_LZ4
	_cleanup_free_ char *buf = NULL, *out = NULL;
	size_t buf_size = 0;
	LZ4_streamDecode_t lz4_data = {};
	le32_t header;
	size_t total_in = sizeof(header), total_out = 0;

	assert(fdf >= 0);
	assert(fdt >= 0);

	out = malloc(4 * LZ4_BUFSIZE);
	if (!out)
		return log_oom();

	for (;;) {
		ssize_t n, m;
		int r;

		n = read(fdf, &header, sizeof(header));
		if (n < 0)
			return -errno;
		if (n != sizeof(header))
			return errno ? -errno : -EIO;

		m = le32toh(header);
		if (m == 0)
			break;

		/* We refuse to use a bigger decompression buffer than
                 * the one used for compression by 4 times. This means
                 * that compression buffer size can be enlarged 4
                 * times. This can be changed, but old binaries might
                 * not accept buffers compressed by newer binaries then.
                 */
		if (m > LZ4_COMPRESSBOUND(LZ4_BUFSIZE * 4)) {
			log_error("Compressed stream block too big: %zd bytes",
				m);
			return -EBADMSG;
		}

		total_in += sizeof(header) + m;

		if (!GREEDY_REALLOC(buf, buf_size, m))
			return log_oom();

		errno = 0;
		n = loop_read(fdf, buf, m, false);
		if (n < 0)
			return n;
		if (n != m)
			return errno ? -errno : -EIO;

		r = LZ4_decompress_safe_continue(&lz4_data, buf, out, m,
			4 * LZ4_BUFSIZE);
		if (r <= 0)
			log_error("LZ4 decompression failed.");

		total_out += r;

		if (max_bytes != -1 && total_out > (size_t)max_bytes) {
			log_debug("Decompressed stream longer than %zd bytes",
				(size_t)max_bytes);
			return -EFBIG;
		}

		n = loop_write(fdt, out, r, false);
		if (n < 0)
			return n;
	}

	log_debug("LZ4 decompression finished (%zu -> %zu bytes, %.1f%%)",
		total_in, total_out, (double)total_out / total_in * 100);

	return 0;
#else
	log_error("Cannot decompress file. Compiled without LZ4 support.");
	return -EPROTONOSUPPORT;
#endif
}

int
decompress_stream(const char *filename, int fdf, int fdt, off_t max_bytes)
{
	if (endswith(filename, ".lz4"))
		return decompress_stream_lz4(fdf, fdt, max_bytes);
	else if (endswith(filename, ".xz"))
		return decompress_stream_xz(fdf, fdt, max_bytes);
	else
		return -EPROTONOSUPPORT;
}
