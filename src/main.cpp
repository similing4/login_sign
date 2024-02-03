#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdlib.h>
#include <io.h>

void base64(const unsigned char *input,char *output, int length)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  memcpy(output, bptr->data, bptr->length-1);
  output[bptr->length-1] = 0;

  BIO_free_all(b64);
}

int private_key_sign(const unsigned char *input,int inputlen, const char *pri_key_fn, char *retstr)
{
    RSA* p_rsa = NULL;
    FILE* file = NULL;
    char data[4096];
    int nid;
    unsigned int signlen;
    int i = 0;
    int ret = 0;

    nid = NID_md5;

    file = fopen(pri_key_fn, "rb");
    if (!file)
    {
        ret = -1;
        return ret;
    }

    if ((p_rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL)) == NULL)
    {
        ret = -2;
        fclose(file);
        return ret;
    }

    fclose(file);

    ret = RSA_private_encrypt(inputlen, (const unsigned char*)input, (unsigned char *)data, p_rsa, RSA_PKCS1_PADDING);
          
    if (ret < 1)
        return -3;
    signlen = ret;
    char base64val[540];
    base64((unsigned char *)data, base64val, signlen);
    int len = strlen(base64val);
    if(len<0 || len>539)
        return -4;
    int j=0;
    for(int i=0;i<len;i++){
        if(base64val[i] == '\n')
            continue;
        retstr[j] = base64val[i];
        j++;
    }
    retstr[j] = '\0';
    RSA_free(p_rsa);
    return 0;
}

extern int signUidToStartParam(int uid, const char *pem, char *dst)
{
    unsigned char src[46] = {0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x55,0x91,0x45,0x10,0x01,0x04,0x03,0x03,0x01,0x01};
    src[3] = uid & 0xFF;
    src[2] = (uid >> 8) & 0xFF;
    src[1] = (uid >> 16) & 0xFF;
    src[0] = (uid >> 24) & 0xFF;
    if (private_key_sign(src, 46, pem, dst))
        return 0;
    return 1;
}

int to_unsigned_number(const char *input){
    int len = strlen(input);
    if(len > 12)
        return -1;
    if(len == 0)
        return -1;
    int ret = 0;
    for(int i=0;i<len;i++) {
        ret = ret * 10;
        if('0' > input[i] || '9' < input[i])
            return -1;
        ret += input[i] - '0';
    }
    return ret;
}

int main(int argc, char *argv[])
{
    if(argc < 3){
        printf("Usage: loginSign.exe [uid] [pem file]\n");
        return 0;
    }
    int uid = to_unsigned_number(argv[1]);
    char *pem = argv[2];
    if(uid < 0) {
        printf("Invalid UID!\n");
        return 1;
    }
    if(access(pem, F_OK)) {
        printf("File %s not exists!\n", pem);
        return 1;
    }   

    //公私钥生成命令：
    //openssl genrsa -out privatekey.pem 2048
    //openssl rsa -in privatekey.pem -pubout -out publickey.pem
    char res[1024];
    int isSuccess = signUidToStartParam(uid, pem, res); //参数1是用户的UID，参数2是私钥，参数3是返回值
    if(isSuccess)
        printf("%s\n", res);
    else
        return 1;
    return 0;
}