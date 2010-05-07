
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
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
