#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <openssl/applink.c>
// Electrum_HD_rewrite_C++.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "mnemonic.h"
#include "version.h"
//User defined files
#include "BIP32_KeyStore.h";
#include "BIP32Node.h";
//APIs


#include<string>
#include <iostream>
#include <fstream>
//Function declarations.
void write_data_to_file(std::string seed, std::string XPRV_store, std::string XPUB_store, std::string type);
///////////////////////////////////////////
int main(void)
{
        std::string type = "bip32";
        mnemonic* Mnemonic = new mnemonic();
        //Run the solver, produces Mnemonic words, master_k and master_c
        Mnemonic->Main_Solver();
        //Brings out all relevant data from Mnemonic object. 
        std::string seed = Mnemonic->get_seed();
        std::string I = Mnemonic->get_I();
        BIP32Node* Node = new BIP32Node;
        Node->Main_Solver(*Node, I);

        std::string XPRV_store = Node->get_XPRV_key();
        std::string XPUB_store = Node->get_XPUB_key();

        write_data_to_file(seed, XPRV_store, XPUB_store, type);
    return 0;
}

void write_data_to_file(std::string seed, std::string XPRV_store, std::string XPUB_store, std::string type) {
    
    std::ofstream myfile;

    //myfile.open("wallet_details.txt");
    myfile.open("..\\data_output\\wallet_details.txt");
    myfile << "{" << std::endl;
    myfile << "keystore: {" << std::endl;
    myfile << "    \"derivation\": " << "\"m\"" << std::endl;
    myfile << "    \"seed\": " << seed << std::endl;
    myfile << "    \"type\": " << type << std::endl;
    myfile << "    \"xprv\": " << XPUB_store << std::endl;
    myfile << "    \"xpub\": " << XPRV_store << std::endl;
    myfile << "          }" << std::endl;
    myfile << "}" << std::endl;
    myfile.close();
}