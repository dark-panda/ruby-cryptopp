/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JSKIPJACK_H__
#define __JSKIPJACK_H__

#include "jconfig.h"

#if ENABLED_SKIPJACK_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "skipjack.h"

using namespace CryptoPP;

class JSKIPJACK : public JCipher_Template<SKIPJACK_Info, SKIPJACK_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
