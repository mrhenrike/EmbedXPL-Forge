/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2008 Axel Gembe <ago@bastart.eu.org>
 * Copyright (C) 2009 Daniel Dickinson <crazycshore@gmail.com>
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netinet/in.h>
 
 
#define IMAGE_LEN 10                   /* Length of Length Field */
#define ADDRESS_LEN 12                 /* Length of Address field */
#define TAGID_LEN  6                   /* Length of tag ID */
#define TAGINFO_LEN 20                 /* Length of vendor information field in tag */
#define TAGVER_LEN 4                   /* Length of Tag Version */
#define TAGLAYOUT_LEN 4                /* Length of FlashLayoutVer */
 
#define NUM_TAGID 5
#define IMAGETAG_CRC_START		0xFFFFFFFF
 
struct tagiddesc_t {
  char tagid[TAGID_LEN + 1];
  char tagiddesc[80];
};
 
 // bc221 is used by BT Voyager and should be right
 // bc310 should be right, and may apply to 3.08 code as well
#define TAGID_DEFINITIONS { \
  { "bccfe", "Broadcom CFE flash image" }, \
  { "bc300", "Broadcom code version 3.00-3.06 and all ftp/tftp flash" }, \
  { "ag306", "Alice Gate (Pirelli, based on Broadcom 3.06)" }, \
  { "bc221", "Broadcom code version 2.21" }, \
  { "bc310", "Broadcom code version 3.10-3.12" }, \
}
 
struct bcm_tag_bccfe {
	unsigned char tagVersion[TAGVER_LEN];           // 0-3: Version of the image tag
	unsigned char sig_1[20];                        // 4-23: Company Line 1
	unsigned char sig_2[14];                        // 24-37: Company Line 2
	unsigned char chipid[6];                        // 38-43: Chip this image is for
	unsigned char boardid[16];                      // 44-59: Board name
	unsigned char big_endian[2];                    // 60-61: Map endianness -- 1 BE 0 LE
	unsigned char totalLength[IMAGE_LEN];           // 62-71: Total length of image
	unsigned char cfeAddress[ADDRESS_LEN];          // 72-83: Address in memory of CFE
	unsigned char cfeLength[IMAGE_LEN];             // 84-93: Size of CFE
	unsigned char rootAddress[ADDRESS_LEN];         // 94-105: Address in memory of rootfs
	unsigned char rootLength[IMAGE_LEN];            // 106-115: Size of rootfs
	unsigned char kernelAddress[ADDRESS_LEN];       // 116-127: Address in memory of kernel
	unsigned char kernelLength[IMAGE_LEN];          // 128-137: Size of kernel
	unsigned char dualImage[2];                     // 138-139: Unused at present
	unsigned char inactiveFlag[2];                  // 140-141: Unused at present
    unsigned char information1[TAGINFO_LEN];        // 142-161: Unused at present
    unsigned char tagId[TAGID_LEN];                 // 162-167: Identifies which type of tag this is, currently two-letter company code, and then three digits for version of broadcom code in which this tag was first introduced
    unsigned char tagIdCRC[4];                      // 168-171: CRC32 of tagId
	unsigned char reserved1[44];                    // 172-215: Reserved area not in use
	unsigned char imageCRC[4];                      // 216-219: CRC32 of images
    unsigned char reserved2[16];                    // 220-235: Unused at present
    unsigned char headerCRC[4];                     // 236-239: CRC32 of header excluding tagVersion
    unsigned char reserved3[16];                    // 240-255: Unused at present
};
 
struct bcm_tag_bc300 {
	unsigned char tagVersion[TAGVER_LEN];           // 0-3: Version of the image tag
	unsigned char sig_1[20];                        // 4-23: Company Line 1
	unsigned char sig_2[14];                        // 24-37: Company Line 2
	unsigned char chipid[6];                        // 38-43: Chip this image is for
	unsigned char boardid[16];                      // 44-59: Board name
	unsigned char big_endian[2];                    // 60-61: Map endianness -- 1 BE 0 LE
	unsigned char totalLength[IMAGE_LEN];           // 62-71: Total length of image
	unsigned char cfeAddress[ADDRESS_LEN];          // 72-83: Address in memory of CFE
	unsigned char cfeLength[IMAGE_LEN];             // 84-93: Size of CFE
	unsigned char flashImageStart[ADDRESS_LEN];     // 94-105: Address in memory of kernel (start of image)
	unsigned char flashRootLength[IMAGE_LEN];       // 106-115: Size of rootfs + deadcode (web flash uses this + kernelLength to determine the size of the kernel+rootfs flash image)
 	unsigned char kernelAddress[ADDRESS_LEN];       // 116-127: Address in memory of kernel
	unsigned char kernelLength[IMAGE_LEN];          // 128-137: Size of kernel
	unsigned char dualImage[2];                     // 138-139: Unused at present
	unsigned char inactiveFlag[2];                  // 140-141: Unused at present
    unsigned char information1[TAGINFO_LEN];        // 142-161: Unused at present
    unsigned char tagId[TAGID_LEN];                 // 162-167: Identifies which type of tag this is, currently two-letter company code, and then three digits for version of broadcom code in which this tag was first introduced
    unsigned char tagIdCRC[4];                      // 168-173: CRC32 to ensure validity of tagId
    unsigned char rootAddress[ADDRESS_LEN];         // 174-183: Address in memory of rootfs partition
    unsigned char rootLength[IMAGE_LEN];            // 184-193: Size of rootfs partition
	unsigned char reserved1[22];                    // 194-215: Reserved area not in use
	unsigned char imageCRC[4];                      // 216-219: CRC32 of images
    unsigned char reserved2[16];                    // 220-235: Unused at present
    unsigned char headerCRC[4];                     // 236-239: CRC32 of header excluding tagVersion
    unsigned char reserved3[16];                    // 240-255: Unused at present
};
 
struct bcm_tag_ag306 {
	unsigned char tagVersion[TAGVER_LEN];           // 0-3: Version of the image tag
	unsigned char sig_1[20];                        // 4-23: Company Line 1
	unsigned char sig_2[14];                        // 24-37: Company Line 2
	unsigned char chipid[6];                        // 38-43: Chip this image is for
	unsigned char boardid[16];                      // 44-59: Board name
	unsigned char big_endian[2];                    // 60-61: Map endianness -- 1 BE 0 LE
	unsigned char totalLength[IMAGE_LEN];           // 62-71: Total length of image
	unsigned char cfeAddress[ADDRESS_LEN];          // 72-83: Address in memory of CFE
	unsigned char cfeLength[IMAGE_LEN];             // 84-93: Size of CFE
	unsigned char flashImageStart[ADDRESS_LEN];     // 94-105: Address in memory of kernel (start of image)
	unsigned char flashRootLength[IMAGE_LEN];       // 106-115: Size of rootfs + deadcode (web flash uses this + kernelLength to determine the size of the kernel+rootfs flash image)
 	unsigned char kernelAddress[ADDRESS_LEN];       // 116-127: Address in memory of kernel
	unsigned char kernelLength[IMAGE_LEN];          // 128-137: Size of kernel
	unsigned char dualImage[2];                     // 138-139: Unused at present
	unsigned char inactiveFlag[2];                  // 140-141: Unused at present
    unsigned char information1[TAGINFO_LEN];        // 142-161: Unused at present
	unsigned char information2[54];                 // 162-215: Compilation and related information (not generated/used by OpenWRT)
	unsigned char kernelCRC[4] ;                    // 216-219: CRC32 of images
    unsigned char rootAddress[ADDRESS_LEN];         // 220-231: Address in memory of rootfs partition
    unsigned char tagIdCRC[4];                      // 232-235: Checksum to ensure validity of tagId
    unsigned char headerCRC[4];                     // 236-239: CRC32 of header excluding tagVersion
	unsigned char rootLength[IMAGE_LEN];            // 240-249: Size of rootfs
    unsigned char tagId[TAGID_LEN];                 // 250-255: Identifies which type of tag this is, currently two-letter company code, and then three digits for version of broadcom code in which this tag was first introduced
};
 
struct bcm_tag_bc221 {
	unsigned char tagVersion[TAGVER_LEN];           // 0-3: Version of the image tag
	unsigned char sig_1[20];                        // 4-23: Company Line 1
	unsigned char sig_2[14];                        // 24-37: Company Line 2
	unsigned char chipid[6];                        // 38-43: Chip this image is for
	unsigned char boardid[16];                      // 44-59: Board name
	unsigned char big_endian[2];                    // 60-61: Map endianness -- 1 BE 0 LE
	unsigned char totalLength[IMAGE_LEN];           // 62-71: Total length of image
	unsigned char cfeAddress[ADDRESS_LEN];          // 72-83: Address in memory of CFE
	unsigned char cfeLength[IMAGE_LEN];             // 84-93: Size of CFE
	unsigned char flashImageStart[ADDRESS_LEN];     // 94-105: Address in memory of kernel (start of image)
	unsigned char flashRootLength[IMAGE_LEN];       // 106-115: Size of rootfs + deadcode (web flash uses this + kernelLength to determine the size of the kernel+rootfs flash image)
 	unsigned char kernelAddress[ADDRESS_LEN];       // 116-127: Address in memory of kernel
	unsigned char kernelLength[IMAGE_LEN];          // 128-137: Size of kernel
	unsigned char dualImage[2];                     // 138-139: Unused at present
	unsigned char inactiveFlag[2];                  // 140-141: Unused at present
    unsigned char rsa_signature[TAGINFO_LEN];       // 142-161: RSA Signature (unused at present; some vendors may use this)
    unsigned char reserved5[2];                     // 162-163: Unused at present
    unsigned char tagId[TAGID_LEN];                 // 164-169: Identifies which type of tag this is, currently two-letter company code, and then three digits for version of broadcom code in which this tag was first introduced
    unsigned char rootAddress[ADDRESS_LEN];         // 170-181: Address in memory of rootfs partition
    unsigned char rootLength[IMAGE_LEN];            // 182-191: Size of rootfs partition
    unsigned char flashLayoutVer[4];                // 192-195: Version flash layout
    unsigned char kernelCRC[4];                     // 196-199: Guessed to be kernel CRC
    unsigned char reserved4[16];                    // 200-215: Reserved area; unused at present
	unsigned char imageCRC[4];                      // 216-219: CRC32 of images
    unsigned char reserved2[12];                    // 220-231: Unused at present
    unsigned char tagIdCRC[4];                      // 232-235: CRC32 to ensure validity of tagId
    unsigned char headerCRC[4];                     // 236-239: CRC32 of header excluding tagVersion
    unsigned char reserved3[16];                    // 240-255: Unused at present
};
 
struct bcm_tag_bc310 {
	unsigned char tagVersion[4];                    // 0-3: Version of the image tag
	unsigned char sig_1[20];                        // 4-23: Company Line 1
	unsigned char sig_2[14];                        // 24-37: Company Line 2
	unsigned char chipid[6];                        // 38-43: Chip this image is for
	unsigned char boardid[16];                      // 44-59: Board name
	unsigned char big_endian[2];                    // 60-61: Map endianness -- 1 BE 0 LE
	unsigned char totalLength[IMAGE_LEN];           // 62-71: Total length of image
	unsigned char cfeAddress[ADDRESS_LEN];          // 72-83: Address in memory of CFE
	unsigned char cfeLength[IMAGE_LEN];             // 84-93: Size of CFE
	unsigned char flashImageStart[ADDRESS_LEN];     // 94-105: Address in memory of kernel (start of image)
	unsigned char flashRootLength[IMAGE_LEN];       // 106-115: Size of rootfs + deadcode (web flash uses this + kernelLength to determine the size of the kernel+rootfs flash image)
 	unsigned char kernelAddress[ADDRESS_LEN];       // 116-127: Address in memory of kernel
	unsigned char kernelLength[IMAGE_LEN];          // 128-137: Size of kernel
	unsigned char dualImage[2];                     // 138-139: Unused at present
	unsigned char inactiveFlag[2];                  // 140-141: Unused at present
    unsigned char information1[TAGINFO_LEN];        // 142-161: Unused at present; Some vendors use this for optional information
    unsigned char tagId[6];                         // 162-167: Identifies which type of tag this is, currently two-letter company code, and then three digits for version of broadcom code in which this tag was first introduced
    unsigned char tagIdCRC[4];                      // 168-171: CRC32 to ensure validity of tagId
    unsigned char rootAddress[ADDRESS_LEN];         // 172-183: Address in memory of rootfs partition
    unsigned char rootLength[IMAGE_LEN];            // 184-193: Size of rootfs partition
	unsigned char reserved1[22];                    // 193-215: Reserved area not in use
	unsigned char imageCRC[4];                      // 216-219: CRC32 of images
    unsigned char rootfsCRC[4];                     // 220-227: CRC32 of rootfs partition
    unsigned char kernelCRC[4];                     // 224-227: CRC32 of kernel partition
    unsigned char reserved2[8];                     // 228-235: Unused at present
    unsigned char headerCRC[4];                     // 235-239: CRC32 of header excluding tagVersion
    unsigned char reserved3[16];                    // 240-255: Unused at present
};
 
union bcm_tag {
  struct bcm_tag_bccfe bccfe;
  struct bcm_tag_bc300 bc300;
  struct bcm_tag_ag306 ag306;
  struct bcm_tag_bc221 bc221;
  struct bcm_tag_bc310 bc310;
};
 
#define IMAGETAG_MAGIC1			"Broadcom Corporatio"
#define IMAGETAG_MAGIC2			"ver. 2.0"
#define IMAGETAG_VER			"6"
#define IMAGETAG_DEFAULT_LOADADDR	0x80010000
#define DEFAULT_FW_OFFSET		0x20000
#define DEFAULT_FLASH_START		0xBFC00000
#define DEFAULT_FLASH_BS		(64 * 2048)
#define DEADCODE			0xDEADC0DE
 
union int2char {
  uint32_t input;
  unsigned char output[4];
};
 
/* This appears to be necessary due to alignment issues */
#define int2tag(tag, value)  intchar.input = htonl(value);	\
	  strncpy(tag, intchar.output, sizeof(union int2char))
 
#define printhex(format, value) printf(format, value, value)
 
/* Kernel header */
struct kernelhdr {
	uint32_t		loadaddr;	/* Kernel load address */
	uint32_t		entry;		/* Kernel entry point address */
	uint32_t		lzmalen;	/* Compressed length of the LZMA data that follows */
};
 
static struct tagiddesc_t tagidtab[NUM_TAGID] = TAGID_DEFINITIONS;
 
static uint32_t crc32tab[256] = {
	0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
	0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
	0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
	0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
	0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
	0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
	0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
	0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
	0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
	0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
	0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
	0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
	0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
	0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
	0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
	0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
	0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
	0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
	0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
	0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
	0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
	0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
	0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
	0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
	0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
	0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
	0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
	0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
	0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
	0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
	0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
	0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};
 
uint32_t crc32(uint32_t crc, uint8_t *data, size_t len)
{
	while (len--)
		crc = (crc >> 8) ^ crc32tab[(crc ^ *data++) & 0xFF];
 
	return crc;
}
 
uint32_t compute_crc32(uint32_t crc, FILE *binfile, size_t compute_start, size_t compute_len)
{
	uint8_t readbuf[1024];
	size_t read;
 
	fseek(binfile, compute_start, SEEK_SET);
 
	/* read block of 1024 bytes */
	while (binfile && !feof(binfile) && !ferror(binfile) && (compute_len >= sizeof(readbuf))) {
		read = fread(readbuf, sizeof(uint8_t), sizeof(readbuf), binfile);
		crc = crc32(crc, readbuf, read);
		compute_len = compute_len - read;
	}
 
	/* Less than 1024 bytes remains, read compute_len bytes */
	if (binfile && !feof(binfile) && !ferror(binfile) && (compute_len > 0)) {
		read = fread(readbuf, sizeof(uint8_t), compute_len, binfile);
		crc = crc32(crc, readbuf, read);
	}
 
	return crc;
}
 
size_t getlen(FILE *fp)
{
	size_t retval, curpos;
 
	if (!fp)
		return 0;
 
	curpos = ftell(fp);
	fseek(fp, 0, SEEK_END);
	retval = ftell(fp);
	fseek(fp, curpos, SEEK_SET);
 
	return retval;
}
 
char *readstring(char *tagstring, size_t length) {
  char *outstring = NULL;
 
  outstring = calloc(length + 1, sizeof(uint8_t));
  strncpy(outstring, tagstring, length);
  return outstring;
}
 
int analyzefile(char *bin, uint32_t fwaddr, char *tagid) {
  FILE *binfile;
  FILE *lzmafile;
  struct bcm_tag_bccfe common_tag;
  union bcm_tag read_tag;
  size_t read, filelen, lzmafilelen;
  char *lzmatmp;
  char lzmaname[255];
  char lzmacmd[1024];
  int lzmafd;
  char *buf;
 
  uint32_t imagelen, kernelAddress, kernelLength, rootAddress, rootLength, imageCRC, kernelCRC, headerCRC, rootfsCRC;
 
  if (bin && !(binfile = fopen(bin, "rb"))) {
    fprintf(stderr, "Unable to open image \"%s\"\n", bin);
    return 1;
  }
 
  filelen = getlen(binfile);
 
  if (!tagid) {
    fprintf(stderr, "No tagid specified\n");
    return 1;
  }
 
  if (fread(&read_tag, sizeof(uint8_t), sizeof(read_tag), binfile) != sizeof(read_tag)) {
    perror("Error reading imagetag\n");
    return 1;
  }
 
  printf("Tag Version: %s\n", readstring(read_tag.bccfe.tagVersion, TAGVER_LEN));
  printf("Signature 1: %s\n", readstring(read_tag.bccfe.sig_1, 20));
  printf("Signature 2: %s\n", readstring(read_tag.bccfe.sig_2, 14));
  printf("Chip ID: %s\n", readstring(read_tag.bccfe.chipid, 6));
  printf("Board ID: %s\n", readstring(read_tag.bccfe.boardid, 16));
  if (read_tag.bccfe.big_endian[0] = '1') {
    printf("Bigendian: true\n");
  } else if (read_tag.bccfe.big_endian[1] = '0') {
    printf("Bigendian: false\n");
  } else {
    printf("Unrecognized value for endianess\n");
  }
  printhex("Image size: %08x, %lu\n", strtoul(readstring(read_tag.bccfe.totalLength, IMAGE_LEN), NULL, 10));
  printhex("CFE Address: %08x, %lu\n", strtoul(readstring(read_tag.bccfe.cfeAddress, ADDRESS_LEN), NULL, 10));
  printhex("CFE Length: %08x, %lu\n", strtoul(readstring(read_tag.bccfe.cfeLength, IMAGE_LEN), NULL, 10));
  rootAddress = strtoul(readstring(read_tag.bccfe.rootAddress, ADDRESS_LEN), NULL, 10);
  printhex("Flash Root Address: %08x, %lu\n", rootAddress);
  rootLength = strtoul(readstring(read_tag.bccfe.rootLength, IMAGE_LEN), NULL, 10);
  printhex("Flash Root Length: %08x, %lu\n", rootLength);
  kernelAddress = strtoul(readstring(read_tag.bccfe.kernelAddress, ADDRESS_LEN), NULL, 10);
  printhex("Flash Kernel Address: %08x, %lu\n", kernelAddress);
  kernelLength = strtoul(readstring(read_tag.bccfe.kernelLength, IMAGE_LEN), NULL, 10);
  printhex("Flash Kernel Length: %08x, %lu\n", kernelLength);
  printf("Vendor information: %s\n", readstring(read_tag.bccfe.information1, TAGINFO_LEN));
  printf("Image CRC: %08x   [Computed Value: %08x]\n", ntohl(*((uint32_t *)&(read_tag.bccfe.imageCRC))), compute_crc32(IMAGETAG_CRC_START, binfile, rootAddress - DEFAULT_FLASH_START, kernelLength + rootLength));
  rootfsCRC = compute_crc32(IMAGETAG_CRC_START, binfile, rootAddress - fwaddr, rootLength);
  printf("Rootfs CRC:             [Computed Value: %08x]\n", htonl(rootfsCRC));
  printf("Image CRC from sections: %08x   [Computed Value: %08x]\n", ntohl(*((uint32_t *)&(read_tag.bccfe.imageCRC))), compute_crc32(rootfsCRC, binfile, kernelAddress - fwaddr, kernelLength));
  printf("Header CRC: %08x   [Computed Value: %08x]\n", ntohl(*((uint32_t *)&(read_tag.bccfe.headerCRC))), compute_crc32(IMAGETAG_CRC_START, binfile, 0, sizeof(read_tag) - 20));
 
  if (strcmp(tagid, "bccfe") == 0) {
  } else if (strcmp(tagid, "bc300") == 0 ) {
  } else if (strcmp(tagid, "bc221") == 0 ) {
    printf("fsKernel CRC: %08x   [Computed Value: %08x]\n", ntohl(*((uint32_t *)&(read_tag.bc221.kernelCRC))), compute_crc32(IMAGETAG_CRC_START, binfile, kernelAddress - fwaddr, kernelLength+rootLength));
  } else if (strcmp(tagid, "ag306") == 0 ) {
    printf("Kernel CRC: %08x   [Computed Value: %08x]\n", ntohl(*((uint32_t *)&(read_tag.ag306.kernelCRC[0]))), compute_crc32(IMAGETAG_CRC_START, binfile, kernelAddress - fwaddr, kernelLength));
  } else if (strcmp(tagid, "bc310") == 0 ) {
    printf("Kernel CRC: %08x   [Computed Value: %08x]\n", ntohl(*((uint32_t *)&(read_tag.bc310.kernelCRC))), compute_crc32(IMAGETAG_CRC_START, binfile, kernelAddress - fwaddr, kernelLength));
    printf("Rootfs CRC_OLD: %08x   [Computed Value: %08x]\n", ntohl(*((uint32_t *)&(read_tag.bc310.rootfsCRC))), compute_crc32(IMAGETAG_CRC_START, binfile, rootAddress - fwaddr, rootLength));
    printf("Rootfs CRC: %08x   [Computed Value: %08x]\n", ntohl(*((uint32_t *)&(read_tag.bc310.rootfsCRC))), compute_crc32(IMAGETAG_CRC_START, binfile, rootAddress - DEFAULT_FLASH_START, rootLength));
  } else {
    fprintf(stderr, "Unrecognized tagid value\n");
    return 1;
  }
  return 0;
}
 
int main(int argc, char **argv)
{
  int c, i;
  char *bin, *tagid;
  uint32_t flashstart, fwoffset, flash_bs;
  uint32_t fwaddr;
  int tagidfound = 0;
 
  bin = tagid =  NULL;
 
  flashstart = DEFAULT_FLASH_START;
  fwoffset = DEFAULT_FW_OFFSET;
  flash_bs = DEFAULT_FLASH_BS;
 
  printf("Broadcom image analyzer - v0.1.0\n");
  printf("Copyright (C) 2009 Daniel Dickinson\n");
 
  while ((c = getopt(argc, argv, "i:s:n:k:ht:")) != -1) {
    switch (c) {
    case 'i':
      bin = optarg;			  
      break;
    case 's':
      flashstart = strtoul(optarg, NULL, 16);
      break;
    case 'n':
      fwoffset = strtoul(optarg, NULL, 16);
      break;
    case 't':
      tagid = optarg;
      break;
    case 'h':
    default:
      fprintf(stderr, "Usage: imagetag <parameters>\n\n");
      fprintf(stderr, " -i <inputfile>          - image to analyze\n");
      fprintf(stderr, "	-s <flashstart> 	- Flash start address (i.e. \"0xBFC00000\"\n");
      fprintf(stderr, "	-n <fwoffset>   	- \n");
      fprintf(stderr, "       -t <tagid> - type if imagetag to create, use 'list' to see available choices");
      fprintf(stderr, "	-h			- Displays this text\n\n");
      return 1;
    }
  }
  tagidfound = 0;
  if (!tagid) {
    fprintf(stderr, "You must specify a tagid (-t)\n");
    return 1;
  } else {
    if (strncmp(tagid, "list", 4) == 0) {
      fprintf(stderr, "\n----------------------------------------\n");
      fprintf(stderr, "\tAvailable tagId:");
      fprintf(stderr, "\n\n");
      for (i = 0; i < NUM_TAGID; i++) {
	    fprintf(stderr, "\t%s\t%s", tagidtab[i].tagid, tagidtab[i].tagiddesc);	
      }
      fprintf(stderr, "\n----------------------------------------\n");
      return 0;	    
    }
  }
 
  if (tagid) {
    for(i = 0; i < NUM_TAGID; i++) {
      if (strncmp(tagid, tagidtab[i].tagid, TAGID_LEN) == 0) {
	    tagidfound = 1;
	    break;
      }
    }
    if (!tagidfound) {
      if (tagid) {
	    fprintf(stderr, "The tagid you selected '%s' does't exist.\n", tagid);
      }
      fprintf(stderr, "Use -t list to see the list of available ids");  
      return 1;
    }
 
    if (!bin) {
      fprintf(stderr, "You must specify the input file with -i\n");
      return 1;
    }
  }
 
  /* Fallback to defaults */
  fwaddr = flashstart + fwoffset;
 
  return analyzefile(bin, fwaddr, tagid);
}
