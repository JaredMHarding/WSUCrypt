#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#define PTBUFSIZE 8
#define CTBUFSIZE 16
#define SUBKEYARRAYSIZE 12
#define KEYBUFSIZE 16

// THANK GOD FOR UNIONS
// iterating through the word and byte arrays 0..3 and 0..7
// will start at LEAST SIGNIFICANT (right most)
// and move to MOST SIGNIFICANT (left most)
typedef union _block {
    uint64_t value;
    uint16_t word[4];
    uint8_t byte[8];
} Block;
// the key will be a global variable
Block KEY;
//global array to hold a round of subkeys
uint8_t Subkey[SUBKEYARRAYSIZE];
int SKIndex;
// global round number, this is reset at the beginning of the convert function
int Round;
// K schedule addition piece, this will change after every access to K()
int KShift;
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
// this function calculates the subkeys for one round ahead of time
uint8_t K() {
    uint8_t subkey;
    if (CurrentMode == encrypt) {
        // left rotate, then get the byte
        KEY.value = lcs(KEY.value,1);
        unsigned int x = 4*Round + KShift;
        subkey = KEY.byte[x % 8];
        // KShift increases by 1 for next time K() is called
        KShift = (KShift+1) % 4;
    }
    else if (CurrentMode == decrypt) {
        // KShift decreases by 1 before x is calculated
        KShift = (KShift+3) % 4;
        // get byte, then right rotate
        unsigned int x = 4*(15-Round) + KShift;
        subkey = KEY.byte[x % 8];
        KEY.value = rcs(KEY.value,1);
    }
    else {// something went wrong
        fprintf(stderr,"Error: CurrentMode was not defined\n");
        exit(1);
    }
    return subkey;
}

void generateSubkeys() {
    if (CurrentMode == encrypt) {
        for (int i = 0;i<SUBKEYARRAYSIZE;i++) {
            Subkey[i] = K();
        }
    }
    else if (CurrentMode == decrypt) {
        for (int i = SUBKEYARRAYSIZE-1;i>=0;i--) {
            Subkey[i] = K();
        }
    }
    else {// something went wrong
        fprintf(stderr,"Error: CurrentMode was not defined\n");
        exit(1);
    }
}

uint16_t G(uint16_t w) {
    uint8_t g1 = (uint8_t) (w >> 8);
    uint8_t g2 = (uint8_t) (w & 0x00ff);
    uint8_t g3 = ftable[g2 ^ Subkey[SKIndex++]] ^ g1;
    uint8_t g4 = ftable[g3 ^ Subkey[SKIndex++]] ^ g2;
    uint8_t g5 = ftable[g4 ^ Subkey[SKIndex++]] ^ g3;
    uint8_t g6 = ftable[g5 ^ Subkey[SKIndex++]] ^ g4;
    return concat(g5,g6);
}

void F(uint16_t r0, uint16_t r1, uint16_t* f0, uint16_t* f1) {
    uint16_t t0 = G(r0);
    uint16_t t1 = G(r1);
    uint8_t subk1 = Subkey[SKIndex++];
    uint8_t subk2 = Subkey[SKIndex++];
    uint32_t temp1 = (t0) + (2*t1) + concat(subk1,subk2);
    (*f0) = temp1 % 0x10000; // mod 2^16
    uint8_t subk3 = Subkey[SKIndex++];
    uint8_t subk4 = Subkey[SKIndex++];
    uint32_t temp2 = (2*t0) + (t1) + concat(subk3,subk4);
    (*f1) = temp2 % 0x10000; // mod 2^16
}
// takes a block of plain text and turns it into cipher text or vice versa
uint64_t convert(uint64_t block) {
    Block R;
    R.value = whiten(block);
    // set up for the while loop
    uint16_t f0 = 0x0000;
    uint16_t f1 = 0x0000;
    Round = 0;
    KShift = 0;
    while (Round < 16) {
        // reset the SubkeyIndex
        SKIndex = 0;
        generateSubkeys();
        F(R.word[3],R.word[2],&f0,&f1);
        // set up R for the next round
        Block nextR;
        nextR.word[3] = R.word[1] ^ f0;
        nextR.word[2] = R.word[0] ^ f1;
        nextR.word[1] = R.word[3];
        nextR.word[0] = R.word[2];
        R.value = nextR.value;
        Round++;
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
    if (argc != 2) {
        fprintf(stderr,"Usage: %s (encrypt OR decrypt)\n",argv[0]);
        exit(1);
    }
    // either way it will have to open a key, so let's do that now
    // key file descriptor
    int keyfd = open("key.txt",O_RDONLY);
    if (keyfd == -1) {
        perror("open(key.txt)");
        exit(1);
    }
    // convert the hex characters to a numerical value
    char keyBuffer[KEYBUFSIZE+1] = {0};
    ssize_t keyBytesRead = read(keyfd,&keyBuffer,KEYBUFSIZE);
    if (keyBytesRead != 16) {
        fprintf(stderr,"Not enough characters to create a key\n");
        exit(1);
    }
    KEY.value = (uint64_t) strtoull(keyBuffer,NULL,16);
    // choose a conversion mode
    if (strncmp(argv[1],"encrypt",7) == 0) {
        CurrentMode = encrypt;
        // plaintext file descriptor
        int ptfd = open("plaintext.txt",O_RDONLY);
        if (ptfd == -1) {
            perror("open(plaintext.txt)");
            exit(1);
        }
        // ciphertext file descriptor
        int ctfd = open("ciphertext.txt",O_WRONLY|O_CREAT|O_TRUNC,S_IRWXU);
        if (ctfd == -1) {
            perror("open(ciphertext.txt)");
            exit(1);
        }
        // ready to read and write
        uint8_t ptBuffer[PTBUFSIZE] = {0};
        ssize_t readBytes;
        while ((readBytes = read(ptfd,&ptBuffer,PTBUFSIZE)) > 0) {
            // pad a partial block using ANSI X.923 byte padding
            if (readBytes < PTBUFSIZE) {
                uint8_t padding = PTBUFSIZE - readBytes;
                ptBuffer[PTBUFSIZE-1] = padding;
                for (int i = PTBUFSIZE-2;i>(readBytes-1);i--) {
                    ptBuffer[i] = 0x00;
                }
            }
            // convert the ptBuffer to a Block type
            Block ptBlock;
            for (int i = 0;i<8;i++) {
                ptBlock.byte[7-i] = ptBuffer[i];
            }
            // now ptBlock is ready to be encrypted
            uint64_t ct = convert(ptBlock.value);
            if (dprintf(ctfd,"%" PRIx64 "",ct) < 0) {
                fprintf(stderr,"Error: %s\n",strerror(errno));
                exit(1);
            }
        }
    }
    else if (strncmp(argv[1],"decrypt",7) == 0) {
        CurrentMode = decrypt;
        // plaintext file descriptor
        int ptfd = open("plaintext.txt",O_WRONLY|O_CREAT|O_TRUNC,S_IRWXU);
        if (ptfd == -1) {
            perror("open(plaintext.txt)");
            exit(1);
        }
        // ciphertext file descriptor
        int ctfd = open("ciphertext.txt",O_RDONLY);
        if (ctfd == -1) {
            perror("open(ciphertext.txt)");
            exit(1);
        }
        // ready to read and write
        char ctBuffer[CTBUFSIZE+1] = {0}; // +1 to always have that null byte
        ssize_t readBytes;
        while ((readBytes = read(ctfd,&ctBuffer,CTBUFSIZE)) > 0) {
            if (readBytes != CTBUFSIZE) {
                // readBytes should always be whole blocks for ciphertext
                fprintf(stderr,"Error: corrupted ciphertext\n");
                exit(1);
            }
            Block ctBlock;
            ctBlock.value = (uint64_t) strtoull(ctBuffer,NULL,16);
            Block ptBlock;
            ptBlock.value = convert(ctBlock.value);
            // convert the 64 bit plaintext into a set of 8 characters
            char ptBuffer[PTBUFSIZE+1] = {0}; // +1 to hold that null byte
            for (int i = 0;i<PTBUFSIZE;i++) {
                ptBuffer[i] = ptBlock.byte[PTBUFSIZE-1-i];
            }
            // now we can write the plaintext to the file
            for (int i = 0;i<PTBUFSIZE;i++) {
                // check for padding
                if (ptBuffer[i] == '\0') {
                    // I know, not very sophisticated
                    break;
                }
                // ok to print now
                if (dprintf(ptfd,"%c",ptBuffer[i]) < 0) {
                    fprintf(stderr,"Error: %s\n",strerror(errno));
                    exit(1);
                }
            }
        }
    }
    else {
        fprintf(stderr,"Usage: %s (encrypt OR decrypt)\n",argv[0]);
        exit(1);
    }
}