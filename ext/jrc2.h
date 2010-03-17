/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JRC2_H__
#define __JRC2_H__

#include "jconfig.h"

#if ENABLED_RC2_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "rc2.h"

using namespace CryptoPP;

class JRC2 : public JCipher_Template<RC2_Info, RC2_CIPHER>
{
	public:
		JRC2();

		unsigned int setEffectiveKeylength(const unsigned int keylength);
		unsigned int getEffectiveKeylength() const;

	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();

		unsigned int itsEffectiveKeylength;
};

#endif
#endif
