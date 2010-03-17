/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __J3WAY_H__
#define __J3WAY_H__

#include "jconfig.h"

#if ENABLED_THREEWAY_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "3way.h"

class J3Way : public JCipher_Template<ThreeWay_Info, THREEWAY_CIPHER, 11, 1, INT_MAX>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
