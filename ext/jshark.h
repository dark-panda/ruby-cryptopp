/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JSHARK_H__
#define __JSHARK_H__

#include "jconfig.h"

#ifdef WORD64_AVAILABLE
#if ENABLED_SHARK_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "shark.h"

using namespace CryptoPP;

class JSHARK : public JCipher_Template<SHARK_Info, SHARK_CIPHER, 6, 2, INT_MAX>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
#endif
