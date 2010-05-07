
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JBASE_H__
#define __JBASE_H__

#include <string>

#include "jhelpers.h"
#include "jconstants.h"
#include "jsink.h"

// Crypto++ headers...

#include "hex.h"
#include "files.h"

using namespace CryptoPP;

class JBase
{
	public:
		JBase();
		virtual ~JBase() {};

		string getPlaintext(const bool hex = false) const;
		string getCiphertext(const bool hex = false) const;
		string getKey(const bool hex = false) const;
		unsigned int getKeylength() const;

		void setPlaintext(const string plaintext, const bool hex = false);
		void setCiphertext(const string ciphertext, const bool hex = false);
		unsigned int setKey(const string key, bool hex = false);
		unsigned int setKeylength(const unsigned int keylength);

		string getRNGName() const;
		static string getRNGName(const enum RNGEnum rng);
		enum RNGEnum getRNG() const;
		enum RNGEnum setRNG(const enum RNGEnum rng);

		string getIV(bool hex = false) const;
		void setIV(string iv, bool hex = false);
		void setRandIV(const unsigned int size);

		virtual unsigned int getDefaultKeylength() const = 0;
		virtual unsigned int getMaxKeylength() const = 0;
		virtual unsigned int getMinKeylength() const = 0;
		virtual unsigned int getMultKeylength() const = 0;
		virtual unsigned int getValidKeylength(const unsigned int keylength) const = 0;
		virtual unsigned int getBlockSize() const = 0;
		virtual enum CipherEnum getCipherType() const = 0;
		virtual string getCipherName() const = 0;

		virtual bool encrypt() = 0;
		virtual bool decrypt() = 0;

		virtual bool encryptRubyIO(VALUE* in, VALUE* out) = 0;
		virtual bool decryptRubyIO(VALUE* in, VALUE* out) = 0;

		/* These are deprecated. They were used before using php_streams. Use them
		   if you're using this code in something other than the cryptopp PHP
		   extension... */
// 		virtual bool encryptFile(const string in, const string out) = 0;
// 		virtual bool decryptFile(const string in, const string out) = 0;

	protected:
		string itsPlaintext;
		string itsCiphertext;
		string itsKey;
		string itsIV;

		unsigned int itsKeylength;
		enum RNGEnum itsRNG;
};

#define getKeyHex() getKey(true)
#define getKeyBin() getKey()

#define getPlaintextHex() getPlaintext(true)
#define getPlaintextBin() getPlaintext()

#define getCiphertextHex() getCiphertext(true)
#define getCiphertextBin() getCiphertext()

#define getIVHex() getIV(true)
#define getIVBin() getIV()

#endif
