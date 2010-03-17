/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JBASICCIPHERINFO_H__
#define __JBASICCIPHERINFO_H__

#include "jcipher.h"
#include "jstream.h"

template <typename INFO, typename BASE>
class JBasicCipherInfo : public BASE
{
	public:
		unsigned int getValidKeylength(const unsigned int length) const;
		unsigned int getDefaultKeylength() const;
		unsigned int getMaxKeylength() const;
		unsigned int getMinKeylength() const;
		unsigned int getMultKeylength() const;
		string getCipherName() const;
		static string getStaticCipherName();
};

template <typename INFO, typename BASE>
unsigned int JBasicCipherInfo<INFO, BASE>::getValidKeylength(const unsigned int keylength) const
{
	return INFO::StaticGetValidKeyLength(keylength);
}

template <typename INFO, typename BASE>
unsigned int JBasicCipherInfo<INFO, BASE>::getDefaultKeylength() const
{
	return INFO::DEFAULT_KEYLENGTH;
}

template <typename INFO, typename BASE>
unsigned int JBasicCipherInfo<INFO, BASE>::getMaxKeylength() const
{
	return INFO::MAX_KEYLENGTH;
}

template <typename INFO, typename BASE>
unsigned int JBasicCipherInfo<INFO, BASE>::getMinKeylength() const
{
	return INFO::MIN_KEYLENGTH;
}

template <typename INFO, typename BASE>
unsigned int JBasicCipherInfo<INFO, BASE>::getMultKeylength() const
{
	if (INFO::MIN_KEYLENGTH == INFO::MAX_KEYLENGTH) {
		return 0;
	}
	else {
		return INFO::StaticGetValidKeyLength(INFO::MIN_KEYLENGTH + 1) - INFO::MIN_KEYLENGTH;
	}
}

template <typename INFO, typename BASE>
string JBasicCipherInfo<INFO, BASE>::getCipherName() const
{
	return INFO::StaticAlgorithmName();
}

template <typename INFO, typename BASE>
string JBasicCipherInfo<INFO, BASE>::getStaticCipherName()
{
	return INFO::StaticAlgorithmName();
}

#endif
