/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jbase.h"

JBase::JBase()
{
	itsPlaintext = "";
	itsIV = "";
	itsRNG = DEFAULT_RNG;
}

string JBase::getPlaintext(const bool hex) const
{
	if (hex) {
		return bin2hex(itsPlaintext);
	}
	else {
		return itsPlaintext;
	}
}

string JBase::getCiphertext(const bool hex) const
{
	if (hex) {
		return bin2hex(itsCiphertext);
	}
	else {
		return itsCiphertext;
	}
}

string JBase::getKey(const bool hex) const
{
	if (hex) {
		return bin2hex(itsKey);
	}
	else {
		return itsKey;
	}
}

unsigned int JBase::getKeylength() const
{
	return itsKeylength;
}

void JBase::setPlaintext(const string plaintext, const bool hex)
{
	if (hex) {
		itsPlaintext = hex2bin(plaintext);
	}
	else {
		itsPlaintext = plaintext;
	}
}

void JBase::setCiphertext(const string ciphertext, const bool hex)
{
	if (hex) {
		itsCiphertext = hex2bin(ciphertext);
	}
	else {
		itsCiphertext = ciphertext;
	}
}

unsigned int JBase::setKey(const string key, const bool hex)
{
	if (hex) {
		itsKey = hex2bin(key);
	}
	else {
		itsKey = key;
	}

	setKeylength(itsKey.length());

	return itsKeylength;
}

unsigned int JBase::setKeylength(const unsigned int keylength)
{
	itsKeylength = getValidKeylength(keylength);
	itsKey.resize(itsKeylength);

	return itsKeylength;
}

string JBase::getRNGName() const
{
	return getRNGName(itsRNG);
}

string JBase::getRNGName(const enum RNGEnum rng)
{
	switch (rng) {
		#ifdef NONBLOCKING_RNG_AVAILABLE
		case NON_BLOCKING_RNG:
			#if defined(CRYPTOPP_WIN32_AVAILABLE) && defined(USE_MS_CRYPTOAPI)
			return "Non-blocking (Microsoft CryptoAPI)";
			#else
			return "Non-blocking (/dev/urandom, etc.)";
			#endif
		#endif

		#ifdef BLOCKING_RNG_AVAILABLE
		case BLOCKING_RNG:
			return "Blocking (/dev/random, etc.)";
		#endif

		case RAND_RNG:
			return "System rand() function";
	}

	return "Unknown";
}

enum RNGEnum JBase::getRNG() const
{
	return itsRNG;
}

enum RNGEnum JBase::setRNG(const enum RNGEnum rng)
{
	#ifdef NONBLOCKING_RNG_AVAILABLE
	if (rng == NON_BLOCKING_RNG) {
		itsRNG = rng;
	}
	#endif

	#ifdef BLOCKING_RNG_AVAILABLE
	if (rng == BLOCKING_RNG) {
		itsRNG = rng;
	}
	#endif

	if (rng == RAND_RNG) {
		itsRNG = rng;
	}

	return itsRNG;
}

string JBase::getIV(bool hex) const
{
	if (hex) {
		return bin2hex(itsIV);
	}
	else {
		return itsIV;
	}
}

void JBase::setIV(string iv, bool hex)
{
	if (hex) {
		itsIV = hex2bin(iv);
	}
	else {
		itsIV = iv;
	}
}

void JBase::setRandIV(const unsigned int size)
{
	itsIV = generateIV(size, itsRNG);
}
