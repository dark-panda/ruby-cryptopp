
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#include "ruby.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "jconfig.h"
#include "jbase.h"
#include "jhash.h"

#include "cryptopp_ruby_api.h"

using namespace std;

VALUE rb_mCryptoPP;
VALUE rb_eCryptoPP_Error;
VALUE rb_cCryptoPP_Cipher;
VALUE rb_cCryptoPP_Digest;
VALUE rb_cCryptoPP_Digest_HMAC;

#define CIPHER_ALGORITHM_X(klass, r, c, s) \
  VALUE rb_cCryptoPP_Cipher_ ## r ;
#include "defs/ciphers.def"

#define CHECKSUM_ALGORITHM_X(klass, r, c, s) \
  VALUE rb_cCryptoPP_Digest_ ## r ;
#include "defs/checksums.def"

#define HASH_ALGORITHM_X(klass, r, c, s) \
  VALUE rb_cCryptoPP_Digest_ ## r ;
#include "defs/hashes.def"

#define HMAC_ALGORITHM_X(klass, r, c, s) \
  VALUE rb_cCryptoPP_Digest_HMAC_ ## r ;
#include "defs/hmacs.def"

/* Marking function for garbage collector. */
void cipher_mark(JBase *c)
{
}

/* Free up memory. */
void cipher_free(JBase *c)
{
  delete c;
}

/* Marking function for garbage collector. */
void hash_mark (JHash *c)
{
}

/* Free up memory. */
void hash_free (JHash *c)
{
  delete c;
}


#define CRYPTOPP_VALUE_FUNC(f) \
  RUBY_METHOD_FUNC(f)
#define CRYPTOPP_DEFINE_CONST(klass, n, c) \
  rb_define_const(klass, n, INT2NUM(c));
#define CRYPTOPP_MODULE_METHOD(m, n, f, a) \
  rb_define_module_function(m, n, CRYPTOPP_VALUE_FUNC(f), a);
#define CRYPTOPP_CLASS_METHOD(c, n, f, a) \
  rb_define_method(rb_cCryptoPP_ ## c, n, CRYPTOPP_VALUE_FUNC(f), a);
#define CRYPTOPP_MODULE_METHOD_ALIAS(m, n, o) \
  rb_define_alias(rb_singleton_class(m), n, o);
#define CRYPTOPP_CLASS_METHOD_ALIAS(c, n, o) \
  rb_define_alias(rb_cCryptoPP_ ## c, n, o);

/* The extension initialization function. */
extern "C" void Init_cryptopp()
{
  /**
   * This is the main CryptoPP module. All of the various Cipher, Digest
   * and HMAC classes are found here.
   *
   * The CryptoPP module contains a handful of module methods that can be
   * used to create new ciphers, digests and HMACs and provide information
   * on the environment and configuration CryptoPP is running with.
   */
  rb_mCryptoPP             = rb_define_module("CryptoPP");

  /**
   * Exception class.
   */
  rb_eCryptoPP_Error       = rb_define_class_under(rb_mCryptoPP, "CryptoPPError", rb_eStandardError);

  /**
   * The base cipher class. This class is not meant to be used directly. It
   * merely serves as the base class for all CryptoPP ciphers.
   *
   * Ciphers can be created either by using the
   * <tt>CryptoPP#cipher_factory</tt> factory method or by instantiating
   * the classes directly. For instance, the following are equivalent:
   *
   *  cipher = CryptoPP.cipher_factory(:aes)
   *  cipher = CryptoPP::AES.new
   *
   * Options include:
   *
   * * <tt>:plaintext</tt> and <tt>:plaintext_hex</tt> - set the plaintext. You
   *   can only use one at a time.
   * * <tt>:ciphertext</tt> and <tt>:ciphertext_hex</tt> - set the ciphertext.
   *   You can only use one at a time.
   * * <tt>:key</tt> and <tt>:key_hex</tt> - set the key. You can only use one
   *   at a time.
   * * <tt>:key_length</tt> - set the length of the key. Normally this is done
   *   automatically, but you can force a different key length if necessary.
   * * <tt>:effective_key_length</tt> - sets the effective key length on RC2
   *   ciphers.
   * * <tt>:rounds</tt> - sets the number of rounds a cipher performs on
   *   block ciphers that support them.
   * * <tt>:rng</tt> - sets the random number generator to be used for things
   *   like creating initialization vectors and such. Not all operating
   *   systems and environments will support all RNGs. You can check which
   *   ones are supported with <tt>CryptoPP#rng_available?</tt>. Possible
   *   values are :blocking, :non_blocking and :rand.
   *
   * All of these options have their equivalent setter and getter methods
   * if you need to modify them after initialization.
   */
  rb_cCryptoPP_Cipher      = rb_define_class_under(rb_mCryptoPP, "Cipher", rb_cObject);

  /**
   * The base Digest class. This class is not meant to be used directly. It
   * merely serves as the base class for all CryptoPP Digests and HMACs.
   */
  rb_cCryptoPP_Digest      = rb_define_class_under(rb_mCryptoPP, "Digest", rb_cObject);

  /**
   * The base HMAC class. This class is not meant to be used directly. It
   * merely serves as the base class for all CryptoPP HMACs.
   */
  rb_cCryptoPP_Digest_HMAC = rb_define_class_under(rb_mCryptoPP, "HMAC", rb_cCryptoPP_Digest);

  rb_undef_alloc_func(rb_cCryptoPP_Cipher);
  rb_undef_alloc_func(rb_cCryptoPP_Digest);
  rb_undef_alloc_func(rb_cCryptoPP_Digest_HMAC);

# define XCRYPTOPP_EXT_VERSION(s) #s
# define CRYPTOPP_EXT_VERSION(s) XCRYPTOPP_EXT_VERSION(s)

  rb_define_const(rb_mCryptoPP, "VERSION",           rb_str_new2(CRYPTOPP_EXT_VERSION(EXT_VERSION_CODE)));
  rb_define_const(rb_mCryptoPP, "CRYPTOPP_VERSION",  INT2NUM(CRYPTOPP_VERSION));

#  define CIPHER_ALGORITHM_X(klass, r, c, s) \
    rb_cCryptoPP_Cipher_ ## r = rb_define_class_under(rb_mCryptoPP, # klass, rb_cCryptoPP_Cipher); \
    rb_define_singleton_method((rb_cCryptoPP_Cipher_ ## r), "new", CRYPTOPP_VALUE_FUNC(rb_cipher_ ## r ##_new), -1);
#  include "defs/ciphers.def"

#  define CHECKSUM_ALGORITHM_X(klass, r, c, s) \
    rb_cCryptoPP_Digest_ ## r = rb_define_class_under(rb_mCryptoPP, # klass, rb_cCryptoPP_Digest); \
    rb_define_singleton_method((rb_cCryptoPP_Digest_ ## r), "new", CRYPTOPP_VALUE_FUNC(rb_digest_ ## r ##_new), -1);
#  include "defs/checksums.def"

#  define HASH_ALGORITHM_X(klass, r, c, s) \
    rb_cCryptoPP_Digest_ ## r = rb_define_class_under(rb_mCryptoPP, # klass, rb_cCryptoPP_Digest); \
    rb_define_singleton_method((rb_cCryptoPP_Digest_ ## r), "new", CRYPTOPP_VALUE_FUNC(rb_digest_ ## r ##_new), -1);
#  include "defs/hashes.def"

#  define HMAC_ALGORITHM_X(klass, r, c, s) \
    rb_cCryptoPP_Digest_HMAC_ ## r = rb_define_class_under(rb_mCryptoPP, # klass, rb_cCryptoPP_Digest_HMAC); \
    rb_define_singleton_method((rb_cCryptoPP_Digest_HMAC_ ## r), "new", CRYPTOPP_VALUE_FUNC(rb_digest_hmac_ ## r ##_new), -1);
#  include "defs/hmacs.def"

  rb_define_module_function(rb_mCryptoPP, "cipher_list",      RUBY_METHOD_FUNC(rb_module_cipher_list),     0); /* in ciphers.cpp */
  rb_define_module_function(rb_mCryptoPP, "cipher_name",      RUBY_METHOD_FUNC(rb_module_cipher_name),     1); /* in ciphers.cpp */
  rb_define_module_function(rb_mCryptoPP, "block_mode_name",  RUBY_METHOD_FUNC(rb_module_block_mode_name), 1); /* in ciphers.cpp */
  rb_define_module_function(rb_mCryptoPP, "padding_name",     RUBY_METHOD_FUNC(rb_module_padding_name),    1); /* in ciphers.cpp */
  rb_define_module_function(rb_mCryptoPP, "rng_name",         RUBY_METHOD_FUNC(rb_module_rng_name),        1); /* in ciphers.cpp */
  rb_define_module_function(rb_mCryptoPP, "cipher_enabled?",  RUBY_METHOD_FUNC(rb_module_cipher_enabled),  1); /* in ciphers.cpp */
  rb_define_module_function(rb_mCryptoPP, "rng_available?",   RUBY_METHOD_FUNC(rb_module_rng_available),   1); /* in ciphers.cpp */

  rb_define_module_function(rb_mCryptoPP, "cipher_factory",   RUBY_METHOD_FUNC(rb_module_cipher_factory),        -1); /* in ciphers.cpp */
  rb_define_module_function(rb_mCryptoPP, "digest_factory",   RUBY_METHOD_FUNC(rb_module_digest_factory),        -1); /* in digests.cpp */
  rb_define_module_function(rb_mCryptoPP, "hmac_factory",     RUBY_METHOD_FUNC(rb_module_hmac_factory),   -1); /* in digests.cpp */

  rb_define_module_function(rb_mCryptoPP, "digest_enabled?",    RUBY_METHOD_FUNC(rb_module_digest_enabled), 1); /* in digests.cpp */
  rb_define_module_function(rb_mCryptoPP, "digest_name",        RUBY_METHOD_FUNC(rb_module_digest_name),    1); /* in digests.cpp */
  rb_define_module_function(rb_mCryptoPP, "digest_list",        RUBY_METHOD_FUNC(rb_module_digest_list),    0); /* in digests.cpp */

  rb_define_alias(rb_singleton_class(rb_mCryptoPP), "hash_enabled?", "digest_enabled?");
  rb_define_alias(rb_singleton_class(rb_mCryptoPP), "hash_name",     "digest_name");
  rb_define_alias(rb_singleton_class(rb_mCryptoPP), "hash_list",     "digest_list");

  rb_define_module_function(rb_mCryptoPP, "digest",          RUBY_METHOD_FUNC(rb_module_digest),     -1); /* in digests.cpp */
  rb_define_module_function(rb_mCryptoPP, "digest_hex",      RUBY_METHOD_FUNC(rb_module_digest_hex), -1); /* in digests.cpp */

  rb_define_alias(rb_singleton_class(rb_mCryptoPP), "hexdigest", "digest_hex");

  rb_define_module_function(rb_mCryptoPP, "digest_io",     RUBY_METHOD_FUNC(rb_module_digest_io),         -1); /* in digests.cpp */
  rb_define_module_function(rb_mCryptoPP, "digest_io_hex", RUBY_METHOD_FUNC(rb_module_digest_io_hex),     -1); /* in digests.cpp */

  rb_define_module_function(rb_mCryptoPP, "digest_hmac",     RUBY_METHOD_FUNC(rb_module_hmac_digest),        -1);  /* in digests.cpp */
  rb_define_module_function(rb_mCryptoPP, "digest_hmac_hex", RUBY_METHOD_FUNC(rb_module_hmac_digest_hex),    -1);  /* in digests.cpp */
  rb_define_module_function(rb_mCryptoPP, "hmac_list",       RUBY_METHOD_FUNC(rb_module_hmac_list),           0);  /* in digests.cpp */

  rb_define_method(rb_cCryptoPP_Cipher, "rand_iv",            RUBY_METHOD_FUNC(rb_cipher_rand_iv),            1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "iv=",                RUBY_METHOD_FUNC(rb_cipher_iv_eq),              1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "iv_hex=",            RUBY_METHOD_FUNC(rb_cipher_iv_hex_eq),          1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "iv",                 RUBY_METHOD_FUNC(rb_cipher_iv),                 0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "iv_hex",             RUBY_METHOD_FUNC(rb_cipher_iv_hex),             0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "block_mode=",        RUBY_METHOD_FUNC(rb_cipher_block_mode_eq),      1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "block_mode",         RUBY_METHOD_FUNC(rb_cipher_block_mode),         0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "padding=",           RUBY_METHOD_FUNC(rb_cipher_padding_eq),         1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "padding",            RUBY_METHOD_FUNC(rb_cipher_padding),            0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "rng=",               RUBY_METHOD_FUNC(rb_cipher_rng_eq),             1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "rng",                RUBY_METHOD_FUNC(rb_cipher_rng),                0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "plaintext=",         RUBY_METHOD_FUNC(rb_cipher_plaintext_eq),       1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "plaintext_hex=",     RUBY_METHOD_FUNC(rb_cipher_plaintext_hex_eq),   1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "plaintext",          RUBY_METHOD_FUNC(rb_cipher_plaintext),          0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "plaintext_hex",      RUBY_METHOD_FUNC(rb_cipher_plaintext_hex),      0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "ciphertext=",        RUBY_METHOD_FUNC(rb_cipher_ciphertext_eq),      1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "ciphertext_hex=",    RUBY_METHOD_FUNC(rb_cipher_ciphertext_hex_eq),  1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "ciphertext",         RUBY_METHOD_FUNC(rb_cipher_ciphertext),         0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "ciphertext_hex",     RUBY_METHOD_FUNC(rb_cipher_ciphertext_hex),     0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "key=",               RUBY_METHOD_FUNC(rb_cipher_key_eq),             1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "key_hex=",           RUBY_METHOD_FUNC(rb_cipher_key_hex_eq),         1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "key",                RUBY_METHOD_FUNC(rb_cipher_key),                0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "key_hex",            RUBY_METHOD_FUNC(rb_cipher_key_hex),            0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "key_length=",        RUBY_METHOD_FUNC(rb_cipher_key_length_eq),      1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "key_length",         RUBY_METHOD_FUNC(rb_cipher_key_length),         0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "default_key_length", RUBY_METHOD_FUNC(rb_cipher_default_key_length), 0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "max_key_length",     RUBY_METHOD_FUNC(rb_cipher_max_key_length),     0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "min_key_length",     RUBY_METHOD_FUNC(rb_cipher_min_key_length),     0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "mult_key_length",    RUBY_METHOD_FUNC(rb_cipher_mult_key_length),    0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "valid_key_length",   RUBY_METHOD_FUNC(rb_cipher_valid_key_length),   1); /* in ciphers.cpp */
#  if ENABLED_RC2_CIPHER
  rb_define_method(rb_cCryptoPP_Cipher_RC2, "effective_key_length=", RUBY_METHOD_FUNC(rb_cipher_effective_key_length_eq), 1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher_RC2, "effective_key_length",  RUBY_METHOD_FUNC(rb_cipher_effective_key_length),    0); /* in ciphers.cpp */
#  endif
  rb_define_method(rb_cCryptoPP_Cipher, "block_size",          RUBY_METHOD_FUNC(rb_cipher_block_size),      1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "rounds=",             RUBY_METHOD_FUNC(rb_cipher_rounds_eq),       1); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "rounds",              RUBY_METHOD_FUNC(rb_cipher_rounds),          0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "algorithm_name",      RUBY_METHOD_FUNC(rb_cipher_algorithm_name),  0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "block_mode_name",     RUBY_METHOD_FUNC(rb_cipher_block_mode_name), 0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "padding_name",        RUBY_METHOD_FUNC(rb_cipher_padding_name),    0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "rng_name",            RUBY_METHOD_FUNC(rb_cipher_rng_name),        0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "cipher_type",         RUBY_METHOD_FUNC(rb_cipher_cipher_type),     0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "encrypt",             RUBY_METHOD_FUNC(rb_cipher_encrypt),         0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "encrypt_hex",         RUBY_METHOD_FUNC(rb_cipher_encrypt_hex),     0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "decrypt",             RUBY_METHOD_FUNC(rb_cipher_decrypt),         0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "decrypt_hex",         RUBY_METHOD_FUNC(rb_cipher_decrypt_hex),     0); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "encrypt_io",          RUBY_METHOD_FUNC(rb_cipher_encrypt_io),      2); /* in ciphers.cpp */
  rb_define_method(rb_cCryptoPP_Cipher, "decrypt_io",          RUBY_METHOD_FUNC(rb_cipher_decrypt_io),      2); /* in ciphers.cpp */

  rb_define_method(rb_cCryptoPP_Digest, "digest",              RUBY_METHOD_FUNC(rb_digest_digest),             0); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "digest_hex",          RUBY_METHOD_FUNC(rb_digest_digest_hex),         0); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "digest=",             RUBY_METHOD_FUNC(rb_digest_digest_eq),          1); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "digest_hex=",         RUBY_METHOD_FUNC(rb_digest_digest_hex_eq),      1); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "plaintext",           RUBY_METHOD_FUNC(rb_digest_plaintext),          0); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "plaintext=",          RUBY_METHOD_FUNC(rb_digest_plaintext_eq),       1); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "plaintext_hex",       RUBY_METHOD_FUNC(rb_digest_plaintext_hex),      0); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "plaintext_hex=",      RUBY_METHOD_FUNC(rb_digest_plaintext_hex_eq),   1); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "calculate",           RUBY_METHOD_FUNC(rb_digest_calculate),          0); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "calculate_hex",       RUBY_METHOD_FUNC(rb_digest_calculate_hex),      0); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "digest_io",           RUBY_METHOD_FUNC(rb_digest_digest_io),          1); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "digest_io_hex",       RUBY_METHOD_FUNC(rb_digest_digest_io_hex),      1); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "update",              RUBY_METHOD_FUNC(rb_digest_update),             1); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "to_s",                RUBY_METHOD_FUNC(rb_digest_digest_hex),         0); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "inspect",             RUBY_METHOD_FUNC(rb_digest_inspect),            0); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "==",                  RUBY_METHOD_FUNC(rb_digest_equals),             1); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "algorithm_name",      RUBY_METHOD_FUNC(rb_digest_algorithm_name),     0); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "clear",               RUBY_METHOD_FUNC(rb_digest_clear),              0); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest, "validate",            RUBY_METHOD_FUNC(rb_digest_validate),           0); /* in digests.cpp */

  rb_define_alias(rb_cCryptoPP_Digest, "hexdigest", "digest_hex");
  rb_define_alias(rb_cCryptoPP_Digest, "hexdigest=", "digest_hex=");
  rb_define_alias(rb_cCryptoPP_Digest, "<<", "update");
  rb_define_alias(rb_cCryptoPP_Digest, "valid?", "validate");

  rb_define_method(rb_cCryptoPP_Digest_HMAC, "key=",           RUBY_METHOD_FUNC(rb_digest_hmac_key_eq),        1); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest_HMAC, "key_hex=",       RUBY_METHOD_FUNC(rb_digest_hmac_key_hex_eq),    1); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest_HMAC, "key",            RUBY_METHOD_FUNC(rb_digest_hmac_key),           0); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest_HMAC, "key_hex",        RUBY_METHOD_FUNC(rb_digest_hmac_key_hex),       0); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest_HMAC, "key_length=",    RUBY_METHOD_FUNC(rb_digest_hmac_key_length_eq), 1); /* in digests.cpp */
  rb_define_method(rb_cCryptoPP_Digest_HMAC, "key_length",     RUBY_METHOD_FUNC(rb_digest_hmac_key_length),    0); /* in digests.cpp */
}
