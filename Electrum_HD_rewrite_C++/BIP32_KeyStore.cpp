#include <string>


#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
//#include <openssl/applink.c>
// Electrum_HD_rewrite_C++.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <string>


#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/dynamic_bitset.hpp> 
#include "BIP32_KeyStore.h"

///////////////////////////////////////////////////////////////////
//CONSTRUCTOR
///////////////////////////////////////////////////////////////////
BIP_KeyStore::BIP_KeyStore()
{
}

///////////////////////////////////////////////////////////////////
//DESTRUCTOR
///////////////////////////////////////////////////////////////////
BIP_KeyStore::~BIP_KeyStore()
{
}


///////////////////////////////////////////////////////////////////
//MEMBER FUNCTIONS
///////////////////////////////////////////////////////////////////
void BIP_KeyStore::from_seed(std::string seed) {
	BIP_KeyStore KeyStore;
	KeyStore.add_seed(seed);

};

void BIP_KeyStore::add_seed(std::string seed) {

};




