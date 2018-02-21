#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

// THANK GOD FOR UNIONS
// iterating through the word and byte arrays 0..4 and 0..8
// will start at LEAST SIGNIFICANT (right most)
// and move to MOST SIGNIFICANT (left most)
typedef union _block {
    uint64_t value;
    uint16_t word[4];
    uint8_t byte[8];
} Block;
// the key will be a global variable
Block KEY;
// the mode will affect how the K function works
enum MODE {encrypt, decrypt};
enum MODE CurrentMode;
// fixed substitution table
uint8_t ftable[256] = {
0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,
0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46};

// This is the whitening function
uint64_t whiten(uint64_t block) {
    return block ^ KEY.value;
}
// left circular shift for 64-bit blocks
uint64_t lcs(uint64_t block, unsigned int shift) {
    return (block << shift) | (block >> (64-shift));
}
// right circular shift for 64-bit blocks
uint64_t rcs(uint64_t block, unsigned int shift) {
    return (block >> shift) | (block << (64-shift));
}
// concatenates two 8-bit bytes into one 16-bit word
uint16_t concat(uint8_t a, uint8_t b) {
    return (a << 8) | (b);
}

uint8_t K(unsigned int x) {
    uint8_t subkey;
    if (CurrentMode == encrypt) {
        // left rotate, then get the byte
        KEY.value = lcs(KEY.value,1);
        subkey = KEY.byte[x % 8];
    }
    else if (CurrentMode == decrypt) {
        // get byte, then right rotate
        subkey = KEY.byte[x % 8];
        KEY.value = rcs(KEY.value,1);
    }
    else {// something went wrong
        fprintf(stderr,"Error: CurrentMode was not defined\n");
        exit(1);
    }
    printf("subkey: 0x%" PRIx8 "\n",subkey);
    return subkey;
}

uint16_t G(uint16_t w, unsigned int round) {
    uint8_t g1 = (uint8_t) (w >> 8);
    printf("g1: 0x%" PRIx8 "\n",g1);
    uint8_t g2 = (uint8_t) (w & 0x00ff);
    printf("g2: 0x%" PRIx8 "\n",g2);
    uint8_t g3 = ftable[g2 ^ K(4*round)] ^ g1;
    printf("g3: 0x%" PRIx8 "\n",g3);
    uint8_t g4 = ftable[g3 ^ K(4*round+1)] ^ g2;
    printf("g4: 0x%" PRIx8 "\n",g4);
    uint8_t g5 = ftable[g4 ^ K(4*round+2)] ^ g3;
    printf("g5: 0x%" PRIx8 "\n",g5);
    uint8_t g6 = ftable[g5 ^ K(4*round+3)] ^ g4;
    printf("g6: 0x%" PRIx8 "\n",g6);
    return concat(g5,g6);
}

void F(uint16_t r0, uint16_t r1, unsigned int round, uint16_t* f0, uint16_t* f1) {
    uint16_t t0 = G(r0,round);
    uint16_t t1 = G(r1,round);
    printf("t0: 0x%" PRIx16 "\n",t0);
    printf("t1: 0x%" PRIx16 "\n",t1);
    uint8_t subk1 = K(4*round);
    uint8_t subk2 = K(4*round+1);
    uint32_t temp1 = (t0) + (2*t1) + concat(subk1,subk2);
    printf("temp1: 0x%" PRIx32 "\n",temp1);
    (*f0) = temp1 % 0x10000; // mod 2^16
    uint8_t subk3 = K(4*round+2);
    uint8_t subk4 = K(4*round+3);
    uint32_t temp2 = (2*t0) + (t1) + concat(subk3,subk4);
    printf("temp2: 0x%" PRIx32 "\n",temp2);
    (*f1) = temp2 % 0x10000; // mod 2^16
    printf("f0: 0x%" PRIx16 "\n",(*f0));
    printf("f1: 0x%" PRIx16 "\n",(*f1));
}
// takes a block of plain text and turns it into cipher text or vice versa
uint64_t convert(uint64_t block) {
    Block R;
    R.value = whiten(block);
    // set up for the while loop
    uint16_t f0 = 0x0000;
    uint16_t f1 = 0x0000;
    unsigned int round = 0;
    while (round < 1) {
        printf("Beginning of Round: %i\n",round);
        F(R.word[3],R.word[2],round,&f0,&f1);
        // set up R for the next round
        Block nextR;
        nextR.word[3] = R.word[1] ^ f0;
        nextR.word[2] = R.word[0] ^ f1;
        nextR.word[1] = R.word[3];
        nextR.word[0] = R.word[2];
        R.value = nextR.value;
        printf("Block: 0x%" PRIx64 "\n",R.value);
        printf("End of Round: %i\n\n",round);
        round++;
    }
    // undo the last swap
    Block y;
    y.word[3] = R.word[1];
    y.word[2] = R.word[0];
    y.word[1] = R.word[3];
    y.word[0] = R.word[2];
    // output whitening step will return the converted text
    return whiten(y.value);
}

int main(int argc, char** argv) {
    /* Testing the inttypes.h print macros
    Block n;
    n.value = 0x123456789abcdef0;
    printf("n.value == 0x%" PRIx64 "\n",n.value);
    for (int i = 0;i<4;i++) {
        printf("n.word[%i] == 0x%" PRIx16 "\n",i,n.word[i]);
    }
    for (int i = 0;i<8;i++) {
        printf("n.byte[%i] == 0x%" PRIx8 "\n",i,n.byte[i]);
    }
    n.byte[0] = 0x55;
    printf("n.value == 0x%" PRIx64 "\n",n.value);
     */
    /* Overflow Test
    uint32_t a = 0x000fffff;
    uint16_t b = 0xffff;
    uint32_t c = a + b;
    printf("c = 0x%" PRIx32 "\n",c);
     */
    /* Whitening Test
    KEY.value = 0xabcdef0123456789;
    Block pt;
    pt.value = 0x0123456789abcdef;
    printf("After whitening: 0x%" PRIx64 "\n",whiten(pt.value));
     */
    KEY.value = 0xabcdef0123456789;
    uint64_t pt = 0xb3db233bb437c713;
    CurrentMode = decrypt;
    // for (int i = 0;i<12;i++) {
        // printf("subkey[%i]: 0x%" PRIx8 "\n",i,K(4*0+(i%4)));
    // }
    uint64_t ct = convert(pt);
    //printf("Ciphertext: 0x%" PRIx64 "\n",ct);
}