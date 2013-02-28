
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jmarc4.h"

#if ENABLED_MARC4_CIPHER

SymmetricCipher* JMARC4::getEncryptionObject()
{
	return new Weak::MARC4((byte*) itsKey.data(), itsKeylength);
}

SymmetricCipher* JMARC4::getDecryptionObject()
{
	return getEncryptionObject();
}

#endif
