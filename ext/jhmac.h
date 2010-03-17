/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JHMAC_H__
#define __JHMAC_H__

#include "jhash.h"

using namespace CryptoPP;

class JHMAC : public JHash
{
	public:
		JHMAC(string plaintext = "") : JHash(plaintext)
		{
			itsKeylength = 16;
		}

		unsigned int getKeylength() const;
		string getKey(const bool hex = false) const;

		unsigned int setKeylength(const unsigned int keylength);
		unsigned int setKey(const string key, const bool hex = false);

	protected:
		string itsKey;
		unsigned int itsKeylength;
};

#endif
