
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
