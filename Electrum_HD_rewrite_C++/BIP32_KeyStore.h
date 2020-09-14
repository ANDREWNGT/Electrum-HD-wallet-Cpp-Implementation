#pragma once

#ifndef this_BIP_KeyStore
#define this_BIP_KeyStore


#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
//#include <openssl/applink.c>
// Electrum_HD_rewrite_C++.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <string>

#include <hdkeys.h>
#include <Base58Check.h>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/dynamic_bitset.hpp> 

class BIP_KeyStore
{
public:
	BIP_KeyStore();
	~BIP_KeyStore();

	void from_seed(std::string seed);
	void add_seed(std::string seed);


	//Methods
private:
	BIP_KeyStore* KeyStore = nullptr; // Poisson solver object
	//The hash of the mnemonic seed must begin with this
	std::string seed;

	std::string type = "bip32";

};

#endif
