/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jhmac.h"

unsigned int JHMAC::getKeylength() const
{
	return itsKeylength;
}

string JHMAC::getKey(const bool hex) const
{
	if (hex) {
		return bin2hex(itsKey);
	}
	else {
		return itsKey;
	}
}

unsigned int JHMAC::setKeylength(const unsigned int keylength)
{
	itsKeylength = checkBounds(keylength, 0, UINT_MAX);

	return itsKeylength;
}

unsigned int JHMAC::setKey(const string key, const bool hex)
{
	if (hex) {
		itsKey = hex2bin(key);
	}
	else {
		itsKey = key;
	}

	itsKey.resize(setKeylength(itsKey.length()));

	return itsKeylength;
}
