/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __CRYPTOPP_RUBY_API_H__
#define __CRYPTOPP_RUBY_API_H__

#include "ruby.h"

extern VALUE rb_mCryptoPP;
extern VALUE rb_eCryptoPP_Error;
extern VALUE rb_cCryptoPP_Cipher;
extern VALUE rb_cCryptoPP_Digest;
extern VALUE rb_cCryptoPP_Digest_HMAC;

#define CIPHER_ALGORITHM_X(klass, r, c, s) \
	extern VALUE rb_cCryptoPP_Cipher_ ## r ;
#include "defs/ciphers.def"

#define CHECKSUM_ALGORITHM_X(klass, r, c, s) \
	extern VALUE rb_cCryptoPP_Digest_ ## r ;
#include "defs/checksums.def"

#define HASH_ALGORITHM_X(klass, r, c, s) \
	extern VALUE rb_cCryptoPP_Digest_ ## r ;
#include "defs/hashes.def"

#define HMAC_ALGORITHM_X(klass, r, c, s) \
	extern VALUE rb_cCryptoPP_Digest_HMAC_ ## r ;
#include "defs/hmacs.def"

VALUE rb_module_cipher_factory(int argc, VALUE *argv, VALUE self);
#define CIPHER_ALGORITHM_X(klass, r, n, s) \
VALUE rb_cipher_ ## r ##_new(int argc, VALUE *argv, VALUE self);
#include "defs/ciphers.def"
VALUE rb_cipher_rand_iv(VALUE self, VALUE l);
VALUE rb_cipher_iv_eq(VALUE self, VALUE iv);
VALUE rb_cipher_iv_hex_eq(VALUE self, VALUE iv);
VALUE rb_cipher_iv(VALUE self);
VALUE rb_cipher_iv_hex(VALUE self);
VALUE rb_cipher_block_mode_eq(VALUE self, VALUE m);
VALUE rb_cipher_block_mode(VALUE self);
VALUE rb_cipher_padding_eq(VALUE self, VALUE p);
VALUE rb_cipher_padding(VALUE self);
VALUE rb_cipher_rng_eq(VALUE self, VALUE r);
VALUE rb_cipher_rng(VALUE self);
VALUE rb_cipher_plaintext_eq(VALUE self, VALUE plaintext);
VALUE rb_cipher_plaintext_hex_eq(VALUE self, VALUE plaintext);
VALUE rb_cipher_plaintext(VALUE self);
VALUE rb_cipher_plaintext_hex(VALUE self);
VALUE rb_cipher_ciphertext_eq(VALUE self, VALUE ciphertext);
VALUE rb_cipher_ciphertext_hex_eq(VALUE self, VALUE ciphertext);
VALUE rb_cipher_ciphertext(VALUE self);
VALUE rb_cipher_ciphertext_hex(VALUE self);
VALUE rb_cipher_key_eq(VALUE self, VALUE key);
VALUE rb_cipher_key_hex_eq(VALUE self, VALUE key);
VALUE rb_cipher_key(VALUE self);
VALUE rb_cipher_key_hex(VALUE self);
VALUE rb_cipher_key_length_eq(VALUE self, VALUE l);
VALUE rb_cipher_key_length(VALUE self);
VALUE rb_cipher_default_key_length(VALUE self);
VALUE rb_cipher_min_key_length(VALUE self);
VALUE rb_cipher_max_key_length(VALUE self);
VALUE rb_cipher_mult_key_length(VALUE self);
VALUE rb_cipher_valid_key_length(VALUE self, VALUE l);
VALUE rb_cipher_effective_key_length_eq(VALUE self, VALUE l);
VALUE rb_cipher_effective_key_length(VALUE self);
VALUE rb_cipher_block_size(VALUE self);
VALUE rb_cipher_rounds_eq(VALUE self, VALUE r);
VALUE rb_cipher_rounds(VALUE self);
VALUE rb_cipher_encrypt(VALUE self);
VALUE rb_cipher_encrypt_hex(VALUE self);
VALUE rb_cipher_decrypt(VALUE self);
VALUE rb_cipher_decrypt_hex(VALUE self);
VALUE rb_cipher_encrypt_io(VALUE self, VALUE in, VALUE out);
VALUE rb_cipher_decrypt_io(VALUE self, VALUE in, VALUE out);
VALUE rb_module_cipher_name(VALUE self, VALUE c);
VALUE rb_cipher_algorithm_name(VALUE self);
VALUE rb_module_block_mode_name(VALUE self, VALUE m);
VALUE rb_cipher_block_mode_name(VALUE self);
VALUE rb_module_padding_name(VALUE self, VALUE p);
VALUE rb_cipher_padding_name(VALUE self);
VALUE rb_module_rng_name(VALUE self, VALUE r);
VALUE rb_cipher_rng_name(VALUE self);
VALUE rb_cipher_cipher_type(VALUE self);
VALUE rb_module_cipher_enabled(VALUE self, VALUE c);
VALUE rb_module_rng_available(VALUE self, VALUE r);
VALUE rb_module_cipher_list(VALUE self);
VALUE rb_module_digest_factory(int argc, VALUE *argv, VALUE self);
#define CHECKSUM_ALGORITHM_X(klass, r, n, s) \
VALUE rb_digest_ ## r ##_new(int argc, VALUE *argv, VALUE self);
#include "defs/checksums.def"

#define HASH_ALGORITHM_X(klass, r, n, s) \
VALUE rb_digest_ ## r ##_new(int argc, VALUE *argv, VALUE self);
#include "defs/hashes.def"
VALUE rb_digest_update(VALUE self, VALUE plaintext);
VALUE rb_digest_digest(VALUE self);
VALUE rb_digest_digest_hex(VALUE self);
VALUE rb_digest_plaintext(VALUE self);
VALUE rb_digest_plaintext_hex(VALUE self);
VALUE rb_digest_plaintext_eq(VALUE self, VALUE plaintext);
VALUE rb_digest_plaintext_hex_eq(VALUE self, VALUE plaintext);
VALUE rb_digest_calculate(VALUE self);
VALUE rb_digest_calculate_hex(VALUE self);
VALUE rb_digest_digest_eq(VALUE self, VALUE digest);
VALUE rb_digest_digest_hex_eq(VALUE self, VALUE digest);
VALUE rb_digest_inspect(VALUE self);
VALUE rb_digest_equals(VALUE self, VALUE compare);
VALUE rb_module_digest(int argc, VALUE *argv, VALUE self);
VALUE rb_module_digest_hex(int argc, VALUE *argv, VALUE self);
VALUE rb_module_digest_io(int argc, VALUE *argv, VALUE self);
VALUE rb_module_digest_io_hex(int argc, VALUE *argv, VALUE self);
VALUE rb_module_digest_enabled(VALUE self, VALUE d);
VALUE rb_module_digest_name(VALUE self, VALUE h);
VALUE rb_digest_algorithm_name(VALUE self);
VALUE rb_digest_clear(VALUE self);
VALUE rb_digest_validate(VALUE self);
VALUE rb_digest_digest_io(VALUE self, VALUE io);
VALUE rb_digest_digest_io_hex(VALUE self, VALUE io);
VALUE rb_module_digest_list(VALUE self);
VALUE rb_module_hmac_factory(int argc, VALUE *argv, VALUE self);
#define HMAC_ALGORITHM_X(klass, r, n, s) \
VALUE rb_digest_hmac_ ## r ##_new(int argc, VALUE *argv, VALUE self);
#include "defs/hmacs.def"
VALUE rb_digest_hmac_key_eq(VALUE self, VALUE key);
VALUE rb_digest_hmac_key_hex_eq(VALUE self, VALUE key);
VALUE rb_digest_hmac_key(VALUE self);
VALUE rb_digest_hmac_key_hex(VALUE self);
VALUE rb_digest_hmac_key_length_eq(VALUE self, VALUE l);
VALUE rb_digest_hmac_key_length(VALUE self);
VALUE rb_module_hmac_digest(int argc, VALUE *argv, VALUE self);
VALUE rb_module_hmac_digest_hex(int argc, VALUE *argv, VALUE self);
VALUE rb_module_hmac_list(VALUE self);

#endif
