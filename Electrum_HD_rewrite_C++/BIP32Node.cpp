
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
//#include <openssl/applink.c>
// Electrum_HD_rewrite_C++.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>

#include "BIP32Node.h"


#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#include <hdkeys.h>
#include <Base58Check.h>

#include <cassert>
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

inline uint32_t P(uint32_t i) { return 0x80000000 | i; }
inline bool     isP(uint32_t i) { return 0x80000000 & i; }


///////////////////////////////////////////////////////////////////
//CONSTRUCTOR
///////////////////////////////////////////////////////////////////
BIP32Node::BIP32Node()
{
}

///////////////////////////////////////////////////////////////////
//DESTRUCTOR
///////////////////////////////////////////////////////////////////
BIP32Node::~BIP32Node()
{
}


///////////////////////////////////////////////////////////////////
//MEMBER FUNCTIONS
///////////////////////////////////////////////////////////////////

std::string BIP32Node::S(uint32_t i)
{
    std::stringstream ss;
    ss << (0x7fffffff & i);
    if (isP(i)) { ss << "'"; }
    return ss.str();
}
void BIP32Node::showKey(const Coin::HDKeychain& keychain)
{
    std::cout << "  * ext " << (keychain.isPrivate() ? "prv" : "pub") << ": " << toBase58Check(keychain.extkey()) << std::endl;
}

std::string BIP32Node::storeKey(const Coin::HDKeychain& keychain)
{
    std::string output = (keychain.isPrivate() ? "prv" : "pub") + toBase58Check(keychain.extkey());
    output.erase(0, 3);
    return output;
}

void BIP32Node::showStep(const std::string& chainname, const Coin::HDKeychain& pub, const Coin::HDKeychain& prv)
{
    std::cout << "* [" << chainname << "]" << std::endl;
    showKey(pub);
    showKey(prv);
}

std::string BIP32Node::store_priv_Step(const std::string& chainname,  const Coin::HDKeychain& prv) {
    std::string output= storeKey(prv);
    return output;
}
std::string BIP32Node::store_pub_Step(const std::string& chainname, const Coin::HDKeychain& pub) {
    std::string output=storeKey(pub);
    return output;
}
void BIP32Node::generate_key(const uchar_vector SEED) {

    try {

        //const uint32_t CHAIN[] = { P(2147483647) };
        const uint32_t CHAIN[] = { 0, P(2147483647), 1, P(2147483646), 2 };

        const unsigned int CHAIN_LENGTH = sizeof(CHAIN) / sizeof(uint32_t);

        // Set version
        Coin::HDKeychain::setVersions(0x0488ADE4, 0x0488B21E);
        std::cout << "Master (hex): " << SEED.getHex() << std::endl;

        // Set seed
        Coin::HDSeed hdSeed(SEED);
        bytes_t k = hdSeed.getMasterKey();
        bytes_t c = hdSeed.getMasterChainCode();

        std::stringstream chainname;
        chainname << "Chain m";

        // Create master keychain
        Coin::HDKeychain prv(k, c);
        Coin::HDKeychain pub = prv.getPublic();
        showStep(chainname.str(), pub, prv);
        XPRV=store_priv_Step(chainname.str(), prv);
        XPUB=store_pub_Step(chainname.str(), pub);
        Coin::HDKeychain parentpub;
        
        
        //These lines of code are for the case of multiple child chains. 
        for (unsigned int k = 0; k < CHAIN_LENGTH; k++) {
            // Append subtree label to name
            chainname << "/" << S(CHAIN[k]);
            if (!isP(CHAIN[k]))
                parentpub = pub;
            // Get child private and public keychains
            prv = prv.getChild(CHAIN[k]);
            pub = prv.getPublic();
            // We need to make sure child of pub = pub of child for public derivation 
            if (!isP(CHAIN[k]))
                assert(pub == parentpub.getChild(CHAIN[k]));
                showStep(chainname.str(), pub, prv);
                XPRV=store_priv_Step(chainname.str(), prv);
                XPUB=store_pub_Step(chainname.str(), pub);
        }
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
}

std::string BIP32Node::get_XPUB_key() {
    return XPRV;
}

std::string BIP32Node::get_XPRV_key() {
    return XPUB;
}
std::string BIP32Node::hex_to_string(unsigned char* hex_array, int num_bytes) {
    std::ostringstream oss;
    for (int i = 0; i < num_bytes; ++i)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << +hex_array[i];
    }
    std::string check = oss.str();
    return check;
}
std::string BIP32Node::from_rootseed(std::string seed) {
    unsigned int bytes_length = SHA512_DIGEST_LENGTH;
    unsigned char* output = new unsigned char[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(seed.c_str()), strlen(seed.c_str()), output);
    std::string output_str = hex_to_string(output, bytes_length);
    
    return output_str;
}
unsigned char* BIP32Node::str_to_unsigned_char_ptr(std::string input) {
    const char* intermediate = input.c_str();
    unsigned char* output = reinterpret_cast<unsigned char*>(const_cast<char*>(intermediate));
    return output;
}
//From package <openssl/err.h>
void BIP32Node::handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

std::string BIP32Node::add_xprv_from_seed(BIP32Node Node, std::string seed) {
    std::string rootnode = seed;
    //std::string rootnode = Node.from_rootseed(seed);
    std::string master_k = rootnode.substr(0, rootnode.length() / 2);
    std::string master_c = rootnode.substr(rootnode.length() / 2, rootnode.length());
    return rootnode;
};

void BIP32Node::Main_Solver(BIP32Node Node, std::string seed) {
    std::string I_master = seed;
    generate_key(I_master);
}

