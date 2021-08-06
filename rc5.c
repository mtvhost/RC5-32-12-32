/* Based on RC5REF.C -- Reference implementation of RC5-32/12/16 in C.        */
/* Copyright (C) 1995 RSA Data Security, Inc.                                 */
/* Esteves, Matheus P.; Baleroni, Pedro A. S.; Otsuka, Rafael H.              */
/* Implementation of RC5-32/12/32                                             */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h> // needed for uint32_t

// using uint32_t allow for platform independance
typedef uint32_t WORD;               /* Should be 32-bit = 4 bytes        */
#define w 32                         /* word size in bits                 */
#define r 12                         /* number of rounds                  */
#define b 32                         /* number of bytes in key            */
#define c 8                          /* number  words in key = ceil(8*b/w)*/
#define t 26                         /* size of table S = 2*(r+1) words   */
WORD S[t];                           /* expanded key table                */
WORD P = 0xb7e15163, Q = 0x9e3779b9; /* magic constants                   */
/* Rotation operators. x must be unsigned, to get logical right shift*/
#define ROTL(x, y) (((x) << (y & (w - 1))) | ((x) >> (w - (y & (w - 1)))))
#define ROTR(x, y) (((x) >> (y & (w - 1))) | ((x) << (w - (y & (w - 1)))))

void RC5_ENCRYPT(WORD *pt, WORD *ct) /* 2 WORD input pt/output ct    */
{
  WORD i, A = pt[0] + S[0], B = pt[1] + S[1];
  for (i = 1; i <= r; i++)
  {
    A = ROTL(A ^ B, B) + S[2 * i];
    B = ROTL(B ^ A, A) + S[2 * i + 1];
  }
  ct[0] = A;
  ct[1] = B;
}

void RC5_DECRYPT(WORD *ct, WORD *pt) /* 2 WORD input ct/output pt    */
{
  WORD i, B = ct[1], A = ct[0];
  for (i = r; i > 0; i--)
  {
    B = ROTR(B - S[2 * i + 1], A) ^ A;
    A = ROTR(A - S[2 * i], B) ^ B;
  }
  pt[1] = B - S[1];
  pt[0] = A - S[0];
}

void RC5_SETUP(unsigned char *K) /* secret input key K[0...b-1]      */
{
  WORD i, j, k, u = w / 8, A, B, L[c];
  /* Converting the Secret Key from Bytes to Words */
  for (i = b - 1, L[c - 1] = 0; i != -1; i--)
    L[i / u] = (L[i / u] << 8) + K[i];
  /* Initializing the Array S */
  for (S[0] = P, i = 1; i < t; i++)
    S[i] = S[i - 1] + Q;
  /* Mixing in the Secret Key */
  for (A = B = i = j = k = 0; k < 3 * t; k++, i = (i + 1) % t, j = (j + 1) % c)
  {
    A = S[i] = ROTL(S[i] + (A + B), 3);
    B = L[j] = ROTL(L[j] + (A + B), (A + B));
  }
}

void printword(WORD A)
{
  WORD k;
  for (k = 0; k < w; k += 8)
    printf("%2X", (A >> k) & 0xFF);
}

int main(int argc, char *argv[])
{
  WORD j, pt1[2], pt2[2], ct[2] = {0, 0};
  unsigned char key[b] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char val1[4];
  unsigned char val2[4];
  int i, k, num, num_words;
  char *plaintext;
  // Print key
  printf("key = ");
  for (j = 0; j < b; j++)
    printf("%2X", key[j]);
  printf("\n");
  // Input length of plaintext
  printf("Enter the length of plaintext: ");
  scanf("%d", &num);
  // Print length of plaintext
  printf("Length of plaintext: %d\n", num);
  // Dynamic alocation of memory
  plaintext = (char *)malloc(num * sizeof(char));
  // Input plaintext
  printf("Enter the plaintext: ");
  scanf("%s", plaintext);
  printf("Your plaintext is %s.\n", plaintext);

  // 2 WORD size loop
  for (i = 0; i < num; i += 8)
  {
    for(k = 0; k < 4; k++)
    {
      if((i+k)<num)
        val1[k] = (char) plaintext[i + k];
      else
        val1[k] = (char) 0x00;

      if((i+4+k)<num)
        val2[k] = (char) plaintext[i + 4 + k];
      else
        val2[k] = (char) 0x00;
    }
    printf("\n plaintext ");
    printf("%c%c%c%c%c%c%c%c ", val1[0], val1[1], val1[2], val1[3], val2[0], val2[1], val2[2], val2[3]);
    
    pt1[0] = (int)strtol(val1, NULL, 36);  // Convert String into long integer
	  pt1[1] = (int)strtol(val2, NULL, 36);  // Convert String into long integer

    RC5_SETUP(key);
    RC5_ENCRYPT(pt1, ct);
    RC5_DECRYPT(ct, pt2);

    printf("---> chipertext ");
    printword(ct[0]);
    printword(ct[1]);
    printf("\n");

    if (pt1[0] != pt2[0] || pt1[1] != pt2[1])
      printf("Decryption Error!");
  }
  free(plaintext);
}