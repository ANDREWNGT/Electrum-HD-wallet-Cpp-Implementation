#ifndef this_MNEMONIC
#define this_MNEMONIC


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

#include "version.h"

class mnemonic
{
public:
	mnemonic();
	~mnemonic();

	//Methods
	void handleErrors(void);
	BIGNUM* rand_number_generation();
	std::string* readFile(const int num_words);
	std::string TextToBinaryString(std::string words);
	int word_database_index_generation(char* x);
	void mnemonic_encode(std::string& mnemonic_words, std::string* words_database, std::string empty_space, const int num_words, const BIGNUM* x_source, const BIGNUM* i_source, const BIGNUM* bn_num_words, BN_CTX* ctx);
	std::vector<std::string> split(std::string str, char delimiter);
	BIGNUM* mnemonic_decode(std::string seed, const int num_words, BN_CTX* ctx);
	BIGNUM* FileReadIndex(std::vector<std::string> array, int n, const int num_words, BN_CTX* ctx);
	bool is_new_seed(BIGNUM* rand_gen, std::string seed, std::string prefix);
	void PBKDF2_HMAC_SHA_512_string(const char* pass, const unsigned char* salt, const int32_t iterations, const uint32_t outputBytes, char* hexResult);
	unsigned char** digest_message(char* message, size_t message_len, unsigned char** digest, unsigned int digest_len);
	std::string hex_to_string(unsigned char* hex_array, int num_bytes);
	std::string seed_generation_from_mnemonic();
	std::string root_seed_generation(std::string seed, std::string salt);
	void Main_Solver();
	std::string get_seed();
	std::string get_I();

private:
	mnemonic* Mnemonic = nullptr; // Poisson solver object
	//The hash of the mnemonic seed must begin with this
	std::string seed;
	std::string master_c;
	std::string master_k;
	std::string I;
};

#endif