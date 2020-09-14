
#ifndef this_VERSION
#define this_VERSION


#include <string>

class version
{
public: 
	version();
	~version();

	//Methods
	std::string seed_prefix(std::string seed_type);

private: 
	version *Version = nullptr; // Poisson solver object
	//The hash of the mnemonic seed must begin with this
	std::string SEED_PREFIX = "01";        // Standard wallet
	std::string SEED_PREFIX_SW = "100";    // Segwit wallet
	std::string SEED_PREFIX_2FA = "101";   // Two - factor authentication
	std::string SEED_PREFIX_2FA_SW = "102"; // Two - factor auth, using segwit
};

#endif