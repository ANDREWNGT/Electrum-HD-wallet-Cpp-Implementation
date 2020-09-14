#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
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

#include "mnemonic.h"
#include "version.h"

///////////////////////////////////////////////////////////////////
//CONSTRUCTOR
///////////////////////////////////////////////////////////////////
mnemonic::mnemonic()
{
}

///////////////////////////////////////////////////////////////////
//DESTRUCTOR
///////////////////////////////////////////////////////////////////
mnemonic::~mnemonic()
{
}


///////////////////////////////////////////////////////////////////
//MEMBER FUNCTIONS
///////////////////////////////////////////////////////////////////



BIGNUM* mnemonic::rand_number_generation() {
    /////////////////////////////////////////////////////////////////////////////
    //Random number generation
    //This section generates a random number in the range of 2^121 and 2^132.
    ////////////////////////////////////////////////////////////////////////////
    //set upper limit and lower limit
    // Declare all variables. 
    BN_CTX* ctx; // refers to a cipher context.
    const char* base = "2";
    const char* lower_exponent = "121";
    const char* upper_exponent = "132";
    BIGNUM* a = BN_new();

    BIGNUM* p_lower = BN_new();
    BIGNUM* lower_limit = BN_new();
    BIGNUM* p_upper = BN_new();
    BIGNUM* upper_limit = BN_new();
    /* Create and initialise the context */
    ctx = BN_CTX_new();
    if (!(ctx = BN_CTX_new())) {
        handleErrors();
    }
    // Perform big number arithmetic, functions from <openssl/bn.h>

    //Convert data types for exponent operation. 
    BN_dec2bn(&a, base);
    BN_dec2bn(&p_lower, lower_exponent);
    BN_dec2bn(&p_upper, upper_exponent);

    //Conduct exponent operation
    BN_exp(lower_limit, a, p_lower, ctx);
    BN_exp(upper_limit, a, p_upper, ctx);

    //Convert to decimal format for printing. 
    char* lower_limit_dec = BN_bn2dec(lower_limit);
    char* upper_limit_dec = BN_bn2dec(upper_limit);


    //std::cout << "Lower limit is 2^121, " << lower_limit_dec << ". Number of digits: "<< strlen(lower_limit_dec) << std::endl;
    //std::cout << "Upper limit is 2^132, " << upper_limit_dec << ". Number of digits: "<< strlen(upper_limit_dec) << std::endl;
   //////////////////////////////////////

    BIGNUM* generated_rand = BN_new();
    BIGNUM* tolerance = BN_new();
    BIGNUM* generated_rand_final = BN_new();
    BN_sub(tolerance, upper_limit, lower_limit); //Generates the interval between 2^121 and 2^132
    BN_rand_range(generated_rand, tolerance); //Generates a random number between 0 and tolerance.
    BN_add(generated_rand_final, generated_rand, lower_limit); // Ensures that the generated random number is within 2^121 and 2^132
    char* generated_rand_dec = BN_bn2dec(generated_rand);//Convert to decimal format for verification.
    char* generated_rand_final_dec = BN_bn2dec(generated_rand_final);
    //std::cout << "Alternate generated number:   " << generated_rand_dec << ". Number of digits: " << strlen(generated_rand_dec) << std::endl;
    //std::cout << "Entropy at nonce=0 :" << generated_rand_final_dec << ". Number of digits: " << strlen(generated_rand_final_dec) << std::endl;
    //std::cout << std::endl;
    return generated_rand_final;
    BN_free(a);
    BN_free(p_lower);
    BN_free(lower_limit);
    BN_free(p_upper);
    BN_free(upper_limit);
    BN_free(generated_rand);
    //BN_free(generated_rand_final);
    BN_free(tolerance);
    BN_CTX_free(ctx);
}
std::string* mnemonic::readFile(const int num_words)
{
    //Function that outputs an array of strings that contains all 2048 words from the wordlist/english.txt file. The elements are stored as strings. 
    std::ifstream inFile;
    char inputFilename[] = "in.list";
    inFile.open("wordlist/english.txt");
    std::string* words = new std::string[num_words];
    if (!inFile) {
        throw("Error! Can't open input file.");
    }
    else {
        //    std::cout << "File read success!" << std::endl;
        for (int i = 0; i < num_words; i++)
        {
            inFile >> words[i];
            //std::cout << words[i] << '\n';
        }
        return words;
        inFile.close();
    }
}
std::string mnemonic::TextToBinaryString(std::string words) {
    std::string binaryString = "";
    for (char& _char : words) {
        binaryString += std::bitset<8>(_char).to_string();
    }
    return binaryString;
}
int mnemonic::word_database_index_generation(char* x) {
    std::stringstream strValue;
    strValue << x;
    int y;
    strValue >> y;
    return y;
}
std::vector<std::string> mnemonic::split(std::string str, char delimiter) {
    std::vector<std::string> internal;
    std::stringstream ss(str); // Turn the string into a stream. 
    std::string tok;
    while (getline(ss, tok, delimiter)) {
        internal.push_back(tok);
    }
    return internal;
}
BIGNUM* mnemonic::FileReadIndex(std::vector<std::string> array, int n, const int num_words, BN_CTX* ctx)
{
    //Function that produces the value of BIGNUM* i
    BIGNUM* i = BN_new();
    std::ifstream inFile;
    char inputFilename[] = "in.list";
    inFile.open("wordlist/english.txt");
    std::vector<std::string> words(num_words);
    if (!inFile) {
        std::cerr << "Cant't open input file" << inputFilename << std::endl;
    }
    else {
        //    std::cout << "File read success!" << std::endl;
        for (int p = 0; p < num_words; p++)
        {
            inFile >> words[p];
            //std::cout << words[i] << '\n';
        }
        inFile.close();
    }
    int k;
    BIGNUM* bn_num_words = BN_new();
    BIGNUM* bn_k = BN_new();
    BN_set_word(bn_num_words, num_words);
    std::vector<int>::iterator it;
    while (n > 0) {
        k = std::distance(words.begin(), std::find(words.begin(), words.end(), array[n - 1]));
        BN_set_word(bn_k, k);
        //std::cout << k << std::endl;
        BN_mul(i, i, bn_num_words, ctx); //i*n
        BN_add(i, i, bn_k);
        //i = i * n + k;
        n--;
    }
    char* i_to_print = BN_bn2dec(i);
    //std::cout << "i, FileReadIndex:   " << i_to_print << ". Number of digits: " << strlen(i_to_print) << std::endl;
    return i;
}
BIGNUM* mnemonic::mnemonic_decode(std::string seed, const int num_words, BN_CTX* ctx) {
    // Implement this: words = seed.split()
    // Need to split them by space and stored in an array of strings (words).
    BIGNUM* i = BN_new(); //i=0;
    char delimiter = ' ';
    std::vector<std::string> array = split(seed, delimiter);
    int n = array.size();
    i = FileReadIndex(array, n, num_words, ctx);
    return i;
}
void mnemonic::mnemonic_encode(std::string& mnemonic_words, std::string* words_database, std::string empty_space, const int num_words, const BIGNUM* x_source, const BIGNUM* i_source, const BIGNUM* bn_num_words, BN_CTX* ctx) {
    BIGNUM* i = BN_new();
    BIGNUM* x = BN_new();
    //This section is done to avoid changing the original items.
    BN_copy(i, i_source);
    BN_copy(x, x_source);
    /////////////////////
    char* i_to_print = BN_bn2dec(i);
    while (BN_is_zero(i) == 0) {
        BN_div(NULL, x, i, bn_num_words, ctx); //This means: x=i% num_words;
        BN_div(i, NULL, i, bn_num_words, ctx);//This means: i=i//num_words (Python code)
        char* x_to_print = BN_bn2dec(x);//Convert to decimal format for verification.
        int words_database_index = word_database_index_generation(x_to_print);
        mnemonic_words.append(words_database[words_database_index]);
        mnemonic_words.append(empty_space);
    }
    //mnemonic_words is returned. 
}
std::string mnemonic::hex_to_string(unsigned char* hex_array, int num_bytes) {
    std::ostringstream oss;
    for (int i = 0; i < num_bytes; ++i)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << +hex_array[i];
    }
    std::string check = oss.str();
    return check;
}
bool mnemonic::is_new_seed(BIGNUM* rand_gen, std::string seed, std::string prefix) {
    bool condition = NULL;
    char* s = BN_bn2hex(rand_gen);
    //std::string check = " ";// Line to replace: s = bh2u(hmac_oneshot(b"Seed version", x.encode('utf8'), hashlib.sha512));
    //SHA512_DIGEST_LENGTH
    unsigned int bytes_length = SHA512_DIGEST_LENGTH;
    unsigned char* output = new unsigned char[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(s), strlen(s), output);
    std::string check = hex_to_string(output, bytes_length);
    /*printf("Digest is: ");
    for (int i = 0; i < bytes_length; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");*/
    std::string conduct_check = check.substr(0, prefix.length());
    if (conduct_check.rfind(prefix) != 0) {
        return false;
    }
    else {

        std::cout << "Found a suitable seed!" << std::endl;

        return true;
    }
}
unsigned char** mnemonic::digest_message(char* message, size_t message_len, unsigned char** digest, unsigned int digest_len)
{
    OpenSSL_add_all_digests();

    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();;

    if ((mdctx = EVP_MD_CTX_new()) == NULL)
        handleErrors();

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL))
        handleErrors();


    if (1 != EVP_DigestUpdate(mdctx, message, message_len))
        handleErrors();

    if ((*digest = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_sha512()))) == NULL)
        handleErrors();

    if (1 != EVP_DigestFinal_ex(mdctx, *digest, &digest_len))
        handleErrors();

    return digest;
    EVP_MD_CTX_free(mdctx);
}
void mnemonic::PBKDF2_HMAC_SHA_512_string(const char* pass, const unsigned char* salt, const int32_t iterations, const uint32_t outputBytes, char* hexResult)
{
    unsigned int i;
    unsigned char digest[64];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(reinterpret_cast<const char*>(salt)), iterations, EVP_sha512(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
}
std::string mnemonic::seed_generation_from_mnemonic() {
    //Create a new instance of version. 
    version* Version = new version();
    std::string seed_type = "NULL";
    std::string prefix = Version->seed_prefix(seed_type);
    //Step 1 is written in function rand_number_generation();
    BIGNUM* entropy = rand_number_generation();  //We will make use of entropy for later sections. 
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //Step 2: Read out the data from file wordlist.
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    const int num_words = 2048;
    std::string* words_database = readFile(num_words);
    ///////////////////////////////////////////////////////////////////////////////////////////////////////
    /// Step 3: Generate entire mnemonics string based on method in mnemonics_encode();. 
    ////////////////////////////////////////////////////////////////////////////////
    BIGNUM* i = BN_new();
    // Based off lines 166 to 173. 
    BIGNUM* x = BN_new();
    BN_CTX* ctx; // refers to a cipher context.
    /* Create and initialise the context */
    ctx = BN_CTX_new();
    if (!(ctx = BN_CTX_new())) {
        handleErrors();
    }
    BIGNUM* bn_nonce = BN_new();
    BIGNUM* bn_num_words = BN_new();
    BIGNUM* q = BN_new();
    BN_set_word(bn_num_words, num_words);
    unsigned long nonce = 0;
    std::string empty_space = " ";
    bool loop_condition = true;
    while (true) {
        std::string seed; //Store the 12 words as a string here. We need a new seed every loop. 
        nonce = nonce + 1;
        BN_set_word(bn_nonce, nonce);
        BN_add(i, entropy, bn_nonce); //This means: i=entropy+ nonce

        BIGNUM* i_edit = i;
        mnemonic_encode(seed, words_database, empty_space, num_words, x, i_edit, bn_num_words, ctx);
        q = mnemonic_decode(seed, num_words, ctx);//Reverse the encoding process.
        if (BN_cmp(i, q) != 0) {
            //This if loop checks for whether the seed can yield the same entropy. 
            std::cout << "ERROR, entropy cannot be reverse engineered." << std::endl;
        };
        bool condition_new_seed = is_new_seed(i, seed, prefix);
        //std::cout << std::endl;
        if (condition_new_seed) {
            //std::cout << "Condition is: " << condition_new_seed << std::endl;
            loop_condition = false;
            std::cout << "Success!" << std::endl;
            std::cout << "Mnemonic words are: " << seed << std::endl;
            
            return seed;
            break;
        };
    }
};
std::string mnemonic::root_seed_generation(std::string seed, std::string salt) {
    //Section 1.4 procedure, electrum/bip32.py:from_rootseed()
    const uint32_t outputBytes = SHA512_DIGEST_LENGTH;
    // 2*outputBytes+1 is 2 hex bytes per binary byte, 
    // and one character at the end for the string-terminating \0
    char hexResult[2 * outputBytes + 1];
    memset(hexResult, 0, sizeof(hexResult));
    const int32_t PBKDF2_ROUNDS = 2048;
    const char* seed_char = seed.c_str();
    const char* salt_char = salt.c_str();

    PBKDF2_HMAC_SHA_512_string(seed_char, reinterpret_cast<const unsigned char*>(salt_char), PBKDF2_ROUNDS, outputBytes, hexResult);
    //printf("512-bit hashed seed is %s\n", hexResult);

    unsigned int bytes_length = SHA512_DIGEST_LENGTH;
    unsigned char* output = new unsigned char[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(hexResult), strlen(hexResult), output);
    std::string I = hex_to_string(output, bytes_length);
    //std::string I = hex_to_string(reinterpret_cast<unsigned char*>(hexResult), bytes_length);
    /*
    for (int i = 0; i < bytes_length; i++) {
        printf("%02x", output[i]);
    }

    printf("512 bit hash value is: ");
    for (int i = 0; i < bytes_length; i++) {
        printf("%02x", I[i]);
    }
    printf("\n");
    */
    return I;
};
//From package <openssl/err.h>
void mnemonic::handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void mnemonic::Main_Solver() {
    auto start = high_resolution_clock::now();
    //Part 1
    seed = seed_generation_from_mnemonic();
    //seed = "charge sail water mercy print tuition title baby park rebuild canvas undo";
    //Part 2
    std::string salt = "electrum";
    //Part 3
    I = root_seed_generation(seed, salt);
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<seconds>(stop - start);
    std::cout << "Time to run has been " << duration.count() << " seconds." << std::endl;
};

std::string mnemonic::get_I() {
    return I;
}
std::string mnemonic::get_seed() {
    return seed;
}
