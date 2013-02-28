
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jhash.h"

JHash::JHash(string plaintext, bool hex)
{
	if (hex) {
		itsPlaintext = hex2bin(plaintext);
	}
	else {
		itsPlaintext = plaintext;
	}
	itsHashModule = NULL;
}

JHash::~JHash()
{
	if (itsHashModule != NULL) {
		delete itsHashModule;
	}
}

string JHash::getPlaintext(bool hex) const
{
	if (hex) {
		return bin2hex(itsPlaintext);
	}
	else {
		return itsPlaintext;
	}
}

string JHash::getHashtext(bool hex) const
{
	if (hex) {
		return bin2hex(itsHashtext);
	}
	else {
		return itsHashtext;
	}
}

unsigned int JHash::getDigestSize() const
{
	if (itsHashModule != NULL) {
		return itsHashModule->DigestSize() * 2;
	}
	else {
		return 0;
	}
}

void JHash::setPlaintext(const string plaintext, bool hex)
{
	if (hex) {
		hex2bin(plaintext);
	}
	else {
		itsPlaintext = plaintext;
	}
}

void JHash::setHashtext(const string hashtext, bool hex)
{
	if (hex) {
		itsHashtext = hex2bin(hashtext);
	}
	else {
		itsHashtext = hashtext;
	}
}

void JHash::updatePlaintext(const string plaintext, bool hex)
{
	if (hex) {
		itsPlaintext += hex2bin(plaintext);
	}
	else {
		itsPlaintext += plaintext;
	}
}

void JHash::clear()
{
	itsPlaintext.erase();
	itsHashtext.erase();
}
