#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>


static void EncryptFileBytes(char a, char b, long start, long end, long offset, char c) {
    //printf ("Encrypt! %ld %ld %ld\n", start, end, offset);
}

static void ranges(long __offset) {
  double encrypt_ratio;
  double dVar7;
  long lVar5;
  long i;
  long skip_spread;
  long local_274;
  long local_998;
  char always_0x05 = 0x06;
  bool is_magic_length;

  const char this = NULL;
  const char __fd = NULL;


  if (__offset < 5000) {
    dVar7 = 1.0;
    i = 0;
    encrypt_ratio = 1.0;
LAB_004080d9:
    skip_spread = __offset - i;
    local_998 = skip_spread + 63;
    if (-1 < skip_spread) {
      local_998 = skip_spread;
    }
    local_998 = local_998 >> 6;
    if (always_0x05 == '\x05') {
determine_encrypt_ratio:
      encrypt_ratio = (double)local_998 / dVar7;
      goto encrypt_with_ratio;
    }
  }
  else {
    local_998 = __offset >> 6;
    if (always_0x05 == '\x05') {
                    /* ~214 MB */
      if (0xccccccc < __offset) {
                    /* try { // try from 004082e8 to 004082ec has its CatchHandler @ 00408547 */
//        CryptoPP::/* SymmetricCipherFinal */ void*<>::/* SymmetricCipherFinal */ void*
//                  (local_7f8,(/* SymmetricCipherFinal */ void* *)&keying_interface);
                    /* try { // try from 00408305 to 00408309 has its CatchHandler @ 0040858e */
        EncryptFileBytes(this,__fd,0,50000,__offset,(/* SymmetricCipherFinal */ void*)"local_7f8");
        i = 50000;
//        CryptoPP::/* SymmetricCipherFinal */ void*<>::~/* SymmetricCipherFinal */ void*(local_7f8);
        dVar7 = 50.0;
        encrypt_ratio = 0.02;
        goto LAB_004080d9;
      }
      dVar7 = 3.333333333333333;
      i = 0;
      goto determine_encrypt_ratio;
    }
                    /* 1GB */
    if (0x40000000 < __offset) {
                    /* try { // try from 00408246 to 0040824a has its CatchHandler @ 00408547 */
//      CryptoPP::/* SymmetricCipherFinal */ void*<>::/* SymmetricCipherFinal */ void*
//                (symm_cipher_1,(/* SymmetricCipherFinal */ void* *)&keying_interface);
                    /* try { // try from 00408263 to 00408267 has its CatchHandler @ 00408564 */
      EncryptFileBytes(this,__fd,0,5000,__offset,(/* SymmetricCipherFinal */ void*)"symm_cipher_1");
      i = 5000;
//      CryptoPP::/* SymmetricCipherFinal */ void*<>::~/* SymmetricCipherFinal */ void*(symm_cipher_1);
      dVar7 = 100.0;
      encrypt_ratio = 0.01;
      goto LAB_004080d9;
    }
    encrypt_ratio = 0.3;
    i = 0;
  }
  encrypt_ratio = encrypt_ratio * (double)local_998;
encrypt_with_ratio:
  if ((long)encrypt_ratio == 0) {
    if (0 < __offset) {
                    /* try { // try from 00408005 to 00408009 has its CatchHandler @ 00408547 */
//      CryptoPP::/* SymmetricCipherFinal */ void*<>::/* SymmetricCipherFinal */ void*
//                (symm_cipher,(/* SymmetricCipherFinal */ void* *)&keying_interface");
                    /* try { // try from 00408020 to 00408024 has its CatchHandler @ 004084d8 */
      EncryptFileBytes(this,__fd,0,__offset,__offset,(/* SymmetricCipherFinal */ void*)"symm_cipher");
//      CryptoPP::/* SymmetricCipherFinal */ void*<>::~/* SymmetricCipherFinal */ void*(symm_cipher);
    }
  }
  else {
    skip_spread = local_998 / (long)encrypt_ratio;
    if (skip_spread != 100) {
        printf ("skip %ld: %ld \n", skip_spread, skip_spread * 0x40);
        exit(0);
    } else {
        //exit(1);
        return;
    }
    printf ("skip %ld: %ld \n", skip_spread, skip_spread * 0x40);
    //exit(0);
    if (skip_spread == 0) {
                    /* try { // try from 004081dc to 004081e0 has its CatchHandler @ 00408547 */
//      CryptoPP::/* SymmetricCipherFinal */ void*<>::/* SymmetricCipherFinal */ void*
//                ((/* SymmetricCipherFinal */ void*<> *)symm_cipher_2,(/* SymmetricCipherFinal */ void* *)&keying_interface);
                    /* try { // try from 004081f7 to 004081fb has its CatchHandler @ 0040854f */
      EncryptFileBytes(this,__fd,0,__offset,__offset,(/* SymmetricCipherFinal */ void*)"symm_cipher_2");
//      CryptoPP::/* SymmetricCipherFinal */ void*<>::~/* SymmetricCipherFinal */ void*
//                ((/* SymmetricCipherFinal */ void*<> *)symm_cipher_2);
    }
    else {
      lVar5 = skip_spread;
      if (0 < local_998) {
        do {
          if (((int8_t)(always_0x05 - 5U) < 2) && (local_274 < i + 0x40)) break;
//          CryptoPP::/* SymmetricCipherFinal */ void*<>::/* SymmetricCipherFinal */ void*
//                    ((/* SymmetricCipherFinal */ void*<> *)&symm_cipher_3,
//                     (/* SymmetricCipherFinal */ void* *)&keying_interface);
                    /* try { // try from 004081a2 to 004081a6 has its CatchHandler @ 00408579 */
          EncryptFileBytes(this,__fd,i,0x40,__offset,(/* SymmetricCipherFinal */ void*)"&symm_cipher_3");
//          CryptoPP::/* SymmetricCipherFinal */ void*<>::~/* SymmetricCipherFinal */ void*
//                    ((/* SymmetricCipherFinal */ void*<> *)&symm_cipher_3);
          i = i + skip_spread * 0x40;
          is_magic_length = lVar5 < local_998;
          lVar5 = skip_spread + lVar5;
        } while (is_magic_length);
      }
    }
  }
}

int main(int argc, char* argv[]) {
    const long K = 1024;
    const long M = K * K;
    const long G = M * K;
    if (argc > 1) {
        long a = strtol(argv[1], argv[1+1], 10);
        ranges(a);
    } else {
        fprintf(stderr, "Detecting outliers...");
        for (long a = 1*G+1; a < 1000*G; a++) {
            ranges(a);
        }
        fprintf(stderr, "Out");
    }
}
