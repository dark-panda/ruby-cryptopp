/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jcipher.h"

JCipher::JCipher()
{
	itsMode = ECB_MODE;
	itsPadding = ZEROS_PADDING;
}

string JCipher::getModeName() const
{
	return getModeName(itsMode);
}

string JCipher::getModeName(const enum ModeEnum mode)
{
	switch (mode) {
		case ECB_MODE:
			return "ECB";
		case CBC_MODE:
			return "CBC";
		case CBC_CTS_MODE:
			return "CBC with CTS";
		case CFB_MODE:
			return "CFB";
		case CTR_MODE:
			return "CTR";
		case OFB_MODE:
			return "OFB";
	}

	return "Unknown";
}

enum ModeEnum JCipher::getMode() const
{
	return itsMode;
}

void JCipher::setMode(const enum ModeEnum mode)
{
	itsMode = mode;
	itsPadding = DEFAULT_PADDING;
}

string JCipher::getPaddingName() const
{
	if (itsPadding == DEFAULT_PADDING) {
		if (itsMode == ECB_MODE || itsMode == CBC_MODE)
			return "Default cipher padding (PKCS)";
		else
			return "Default cipher padding (none)";
	}
	else {
		return getPaddingName(itsPadding);
	}
}

string JCipher::getPaddingName(const enum PaddingEnum padding)
{
	switch (padding) {
		case NO_PADDING:
			return "None";
		case ZEROS_PADDING:
			return "Zeroes";
		case PKCS_PADDING:
			return "PKCS";
		case ONE_AND_ZEROS_PADDING:
			return "One and zeroes";
		case DEFAULT_PADDING:
			return "Default cipher padding";
	}

	return "Unknown";
}

enum PaddingEnum JCipher::getPadding() const
{
	return itsPadding;
}

enum PaddingEnum JCipher::setPadding(const enum PaddingEnum padding)
{
	if (padding == NO_PADDING && (itsMode == ECB_MODE || itsMode == CBC_MODE)) {
		return itsPadding;
	}
	else if ((padding == PKCS_PADDING || padding == ONE_AND_ZEROS_PADDING) && (itsMode == CBC_CTS_MODE || itsMode == CTR_MODE || itsMode == OFB_MODE || itsMode == CFB_MODE)) {
		return itsPadding;
	}
	else {
		itsPadding = padding;
		return itsPadding;
	}
}

unsigned int JCipher::getRounds() const
{
	return itsRounds;
}

unsigned int JCipher::setRounds(const unsigned int rounds)
{
	itsRounds = getValidRounds(rounds);

	return itsRounds;
}
