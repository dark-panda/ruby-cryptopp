
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JEXCEPTION_H__
#define __JEXCEPTION_H__

#include <string>
#include "cryptlib.h"

class JException : public CryptoPP::Exception
{
	public:
		explicit JException(const std::string& w) : CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, w) {};
};

#endif
