/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JMARS_H__
#define __JMARS_H__

#include "jconfig.h"

#if ENABLED_MARS_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "mars.h"

using namespace CryptoPP;

class JMARS : public JCipher_Template<MARS_Info, MARS_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
