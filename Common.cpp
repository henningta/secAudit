#include "utils.hpp"
#include "cryptsuite.hpp"
#include "Common.hpp"
#include "Log.hpp"

#include <iostream>

extern FILE *fpErr;

/**
 *      incrementHash
 *
 *      Given an initial hash, hash it a specified number of times
 *	Only works for output being fed as the only input
 *
 *      @param  base    initial hash
 *      @param  count	number of times to repeat hashing
 *      @return string  hashed result after 'count' times
 *
 *      @author Timothy Thong 
 */
std::string Common::incrementHash(const std::string & base, int count) {
	unsigned char *newHash;
	std::string result;
	
	result = base;
	for (int i = 0; i < count; i++) {
        	if ( cryptsuite::calcMD((unsigned char *) &result[0], MD_BYTES, &newHash) ) {
	                result.replace(0, MD_BYTES, (const char *) newHash, MD_BYTES);
                	delete[] newHash;
        	} else {
                	fprintf(fpErr, "Error: Failed to increment hash\n");
        	}   
	}
	return result;
}

/**
 *      hashTypeKey
 *
 *      Hashes log entry type concatenated with key Aj
 *
 *      @param  type    entry type of current LogEntry
 *      @param  keyAj   key from TrustedObject derived by hashes of prev keys
 *      @return string  hash of type concatenated with key
 *
 *      @author Travis Henning
 */
std::string Common::hashTypeKey(EntryType type, const std::string & keyAj) {
        // entry type to string
        std::string entryType = entryTypeToString(type);

        // concatenate with delim || and hash
        std::string concat = entryType + "||" + keyAj;
        unsigned char *outHash = 0x0;
        if (cryptsuite::calcMD(
                                (unsigned char *)concat.c_str(),
                                concat.length(),
                                &outHash) == 0) {
                return 0x0;
        }   

        std::string hashedKey((const char *)outHash, MD_BYTES);
	delete[] outHash;
        return hashedKey;
}

/** 
 *      hashY 
 * 
 *      Hash Yj value of log entry based on prev Yj, encrypted Dj, and Wj 
 * 
 *      @param  prevY                           previous Yj (hashed) value 
 *      @param  encryptedMessage        encrypted Dj of current entry 
 *      @param  entryType                       Wj value of current entry 
 *      @return string                          Yj (hashed) for current entry 
 * 
 *      @author Travis Henning 
 */ 
std::string Common::hashY(const std::string & prevY, 
                const std::string & encryptedMessage, EntryType entryType) { 
        std::string type = entryTypeToString(entryType); 
 
        // concatenate items 
        std::string concat = prevY + "||" + encryptedMessage + "||" + type; 
 
        unsigned char *outHash = 0x0; 
        if (cryptsuite::calcMD( 
                                (unsigned char *)concat.c_str(), 
                                concat.length(), 
                                &outHash) == 0) { 
                return 0x0; 
        } 
 
        std::string hashedY((const char *)outHash, MD_BYTES); 
	delete[] outHash;
        return hashedY; 
} 
 
/** 
 *      hashZ 
 * 
 *      @param  Yj              Yj (hashed) of current entry 
 *      @param  keyAj   current Aj key 
 *      @return string  Zj (hashed) of current entry 
 * 
 *      @author Travis Henning 
 */ 
std::string Common::hashZ(const std::string & Yj, const std::string & keyAj) { 
        unsigned char *outHash = 0x0; 
        if (cryptsuite::calcHMAC( 
                                (unsigned char *)Yj.c_str(), 
                                Yj.length(), 
                                &outHash, 
                                (unsigned char *)keyAj.c_str(), 
                                keyAj.length()) == 0) { 
                return 0x0; 
        } 
 
        std::string hashedZ((const char *)outHash, HMAC_BYTES); 
	delete[] outHash;
        return hashedZ; 
} 

