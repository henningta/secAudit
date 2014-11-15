#include <cstdio>
#include <cstdlib>
#include "debug.hpp"

/**
 * first4Last4 
 *
 * Prints the first 4 and last 4 bytes of a buffer
 *
 * @param	label	buffer identifier to be printed
 * @param	buf	buffer to print
 * @param	len	length of buffer
 *
 * @author              Timothy Thong
 */
void first4Last4(const char *label, unsigned char *buf, size_t len) {

        printf("%-30s", label);

        if (len < 8) {
                size_t i;
                for (i = 0; i < len; i++) printf("0x%02X ", buf[i]); 
        } else {
                printf("0x%02X ", buf[0]); 
                printf("0x%02X ", buf[1]); 
                printf("0x%02X ", buf[2]); 
                printf("0x%02X ", buf[3]); 
                printf(" ...  ");
                printf("0x%02X ", buf[len-4]); 
                printf("0x%02X ", buf[len-3]); 
                printf("0x%02X ", buf[len-2]); 
                printf("0x%02X ", buf[len-1]); 
        }   
        printf("\n");
}
