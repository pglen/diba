// HS crypt block loop

static void hs_encrypt(void *mem, int size2, void *pass, int plen)

{
    int loop; char *pmem = (char*)mem;
    
    for(loop = 0; loop < size2; loop += BLOCKSIZE)
        {
        bluepoint2_encrypt(pmem, BLOCKSIZE, pass, plen);
        pmem += BLOCKSIZE;
        }
}

static void hs_decrypt(void *mem, int size2, void *pass, int plen)

{
    int loop; char *pmem = (char*)mem;
    
    for(loop = 0; loop < size2; loop += BLOCKSIZE)
        {
        bluepoint2_decrypt(pmem, BLOCKSIZE, pass, plen);
        pmem += BLOCKSIZE;
        }
}




