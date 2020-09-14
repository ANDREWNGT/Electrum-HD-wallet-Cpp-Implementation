#pragma once

#ifndef this_BIP32Node
#define this_BIP32Node


#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
//#include <openssl/applink.c>
// Electrum_HD_rewrite_C++.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <string>



#include <hdkeys.h>
#include <Base58Check.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <cmath>
#include <bitset>
#include <cstring> 
#include <fstream>
#include <list>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <chrono> 
using namespace std::chrono;
//using namespace Coin;
class BIP32Node
{
public:
	BIP32Node();
	~BIP32Node();

	static BIP32Node self;

	std::string xtype;
	int depth = 0;
	std::string eckey;
	std::string chaincode;
	std::string fingerprint = "\x00\x00\x00\x00";
	std::string child_number = "\x00\x00\x00\x00";

	//Eckey eckey; //declare an object of type eckey
	
	//Methods
	std::string S(uint32_t i);

	void generate_key(uchar_vector SEED);
	void showKey(const Coin::HDKeychain& keychain);
	std::string storeKey(const Coin::HDKeychain& keychain);
	void showStep(const std::string& chainname, const Coin::HDKeychain& pub, const Coin::HDKeychain& prv);	
	std::string store_priv_Step(const std::string& chainname, const Coin::HDKeychain& prv);
	std::string store_pub_Step(const std::string& chainname, const Coin::HDKeychain& pub);
	
	std::string hex_to_string(unsigned char* hex_array, int num_bytes);
	std::string from_rootseed(std::string seed);
	unsigned char* str_to_unsigned_char_ptr(std::string input);
	void handleErrors(void);

	std::string get_XPRV_key();
	std::string get_XPUB_key();
	std::string add_xprv_from_seed(BIP32Node Node, std::string seed);
	void Main_Solver(BIP32Node Node, std::string seed);
private:
	BIP32Node* Node = nullptr; // Poisson solver object
	std::string XPRV = "";
	std::string XPUB = "";
};

#endif
