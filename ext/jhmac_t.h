
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JHMAC_T_H__
#define __JHMAC_T_H__

#include "jhmac.h"

// Crypto++ headers...

#include "hmac.h"

using namespace CryptoPP;

template <typename HASH, enum HashEnum TYPE>
class JHMAC_Template : public JHMAC
{
	public:
		JHMAC_Template(string plaintext = "");
		inline enum HashEnum getHashType() const;
		bool hash();
		bool validate();
		bool validate(string plaintext, string hashtext);
		string hashRubyIO(VALUE* in, bool hex = true);

		/* This is deprecated. It was used before using php_streams. Use it
		   if you're using this code in something other than the cryptopp PHP
		   extension...*/
		//string hashFile(const string filename, bool hex = true);
};

template <typename HASH, enum HashEnum TYPE>
JHMAC_Template<HASH, TYPE>::JHMAC_Template(string plaintext) : JHMAC(plaintext)
{
	itsHashModule = new HMAC<HASH>;
}

template <typename HASH, enum HashEnum TYPE>
HashEnum JHMAC_Template<HASH, TYPE>::getHashType() const
{
	return TYPE;
}

template <typename HASH, enum HashEnum TYPE>
bool JHMAC_Template<HASH, TYPE>::hash()
{
	((HMAC<HASH>*) itsHashModule)->SetKey((byte*) itsKey.data(), itsKeylength);
	itsHashtext.erase();
	StringSource s(itsPlaintext, true, new HashFilter(*itsHashModule, new StringSink(itsHashtext)));
	return true;
}

template <typename HASH, enum HashEnum TYPE>
bool JHMAC_Template<HASH, TYPE>::validate()
{
	return validate(itsPlaintext, itsHashtext);
}

template <typename HASH, enum HashEnum TYPE>
bool JHMAC_Template<HASH, TYPE>::validate(string plaintext, string hashtext)
{
	if (itsHashModule == NULL) {
		throw;
	}

	((HMAC<HASH>*) itsHashModule)->SetKey((byte*) itsKey.data(), itsKeylength);

	return itsHashModule->VerifyDigest((const byte*) hashtext.data(), (const byte*) plaintext.data(), plaintext.length());
}

template <typename HASH, enum HashEnum TYPE>
string JHMAC_Template<HASH, TYPE>::hashRubyIO(VALUE* in, bool hex)
{
	if (itsHashModule == NULL) {
		throw;
	}

	((HMAC<HASH>*) itsHashModule)->SetKey((byte*) itsKey.data(), itsKeylength);
	string retval;
	try {
		if (hex) {
			RubyIOSource f(&in, true, new HashFilter(*itsHashModule, new HexEncoder(new StringSink(retval), false)));
		}
		else {
			RubyIOSource f(&in, true, new HashFilter(*itsHashModule, new StringSink(retval)));
		}
	}
	catch (Exception e) {
		throw e;
	}
	return retval;
}


/* This is deprecated. It was used before using php_streams. Use it
   if you're using this code in something other than the cryptopp PHP
   extension... */
/*template <typename HASH, enum HashEnum TYPE>
string JHMAC_Template<HASH, TYPE>::hashFile(const string filename, bool hex)
{
	if (itsHashModule == NULL) {
		throw;
	}

	((HMAC<HASH>*) itsHashModule)->SetKey((byte*) itsKey.data(), itsKeylength);
	string retval;
	try {
		if (hex) {
			FileSource f(filename.c_str(), true, new HashFilter(*itsHashModule, new HexEncoder(new StringSink(retval), false)));
		}
		else {
			FileSource f(filename.c_str(), true, new HashFilter(*itsHashModule, new StringSink(retval)));
		}
	}
	catch (FileStore::OpenErr e) {
		throw e;
	}
	return retval;
}*/

#endif
