
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JHASH_H__
#define __JHASH_H__

#include "jsink.h"
#include "jhelpers.h"
#include "jconstants.h"


using namespace CryptoPP;

class JHash
{
	public:
		JHash(string plaintext = "", bool hex = false);
		virtual ~JHash();

		string getPlaintext(bool hex = false) const;
		string getHashtext(bool hex = true) const;
		unsigned int getDigestSize() const;
		virtual enum HashEnum getHashType() const = 0;

		void setPlaintext(string plaintext, bool hex = false);
		void setHashtext(string hashtext, bool hex = true);

		void updatePlaintext(string plaintext, bool hex = false);

		void clear();

		virtual bool hash() = 0;
		virtual bool validate() = 0;
		virtual bool validate(string plaintext, string hashtext) = 0;

		virtual string hashRubyIO(VALUE* in, bool hex = true) = 0;

		/* This is deprecated. It was used before using php_streams. Use it
		   if you're using this code in something other than the cryptopp PHP
		   extension... */
		//virtual string hashFile(const string filename, bool hex = true) = 0;

	protected:
		HashTransformation* itsHashModule;

		string itsPlaintext;
		string itsHashtext;
};

#endif
