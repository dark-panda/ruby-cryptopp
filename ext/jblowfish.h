/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JBLOWFISH_H__
#define __JBLOWFISH_H__

#include "jconfig.h"

#if ENABLED_BLOWFISH_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "blowfish.h"

class JBlowfish : public JCipher_Template<Blowfish_Info, BLOWFISH_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
