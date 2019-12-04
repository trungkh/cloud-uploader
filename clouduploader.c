/*
 * Copyright (c) 2016 · Trung Huynh
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "configini/configini.h"
#include "crypto/encrypt.h"
#include "crypto/decrypt.h"

#include "clouduploader.h"
#include "gdriveuploader.h"
#include "odriveuploader.h"

static uint8_t src_key[] = "000AE21CFFB5";
static uint8_t src_iv[]  = "0AE21CFFB5VNCAGI";

void generate_secret_code(uint8_t * input, int inlength, uint8_t *output)
{
    uint8_t temp[16] = { 0 };
    uint8_t index;

    for (index = 0; index < 16; index++)
        temp[index] = 0;

    index = 0;
    while ((index < 16) && (index < inlength))
    {
        temp[index] = input[index];
        index++;
    }

    temp[0] = temp[0] ^ 0xFA;
    temp[1] = temp[1] ^ 0xAB ^ temp[0];
    temp[2] = temp[2] ^ 0x12 ^ temp[1];
    temp[3] = temp[3] ^ 0x33 ^ temp[2];
    temp[4] = temp[4] ^ 0x45 ^ temp[3];
    temp[5] = temp[5] ^ 0xFF ^ temp[4];
    temp[6] = temp[6] ^ 0x4B ^ temp[5];
    temp[7] = temp[7] ^ 0x57 ^ temp[6];
    temp[8] = temp[8] ^ 0x22 ^ temp[7];
    temp[9] = temp[9] ^ 0x91 ^ temp[8];
    temp[10] = temp[10] ^ 0x9A ^ temp[9];
    temp[11] = temp[11] ^ 0xC7 ^ temp[10];
    temp[12] = temp[12] ^ 0x80 ^ temp[11];
    temp[13] = temp[13] ^ 0x1F ^ temp[12];
    temp[14] = temp[14] ^ 0xD2 ^ temp[13];
    temp[15] = temp[15] ^ 0x6E ^ temp[14];
    for (index = 0; index < 16; index++)
        output[index] = temp[index] + 7;
    output[16] = 0;
}

static int config_encryption(const char *path, const uint8_t *key, char *buff)
{
    int n, m;

    FILE *fp = fopen(path, "wb+");
    if (fp == NULL)
    {
        printf("Cant open config file %s \n", path);
        return -1;
    }

    alawEncryptKeyInit(key, src_iv);
    n = strlen(buff);

    if (n >= 16)
    {
        m = alawEncryptWrapper(buff, n - (n % 16));
        if (m != (n - (n % 16)))
        {
            printf("Error encrypt\n");
            fclose(fp);
            return -1;
        }
    }

    m = fwrite(buff, 1, n, fp);
    if (m < n)
    {
        printf("Error Writing - in %d - out %d\n", n, m);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int config_decryption(const char *path, const uint8_t *key, char *buff, size_t buff_size)
{
    int n, m;

    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
    {
        printf("Cant open config file %s \n", path);
        return -1;
    }

    alawDecryptKeyInit(key, src_iv);
    n = fread(buff, 1, buff_size, fp);

    if (n >= 16)
    {
        m = alawDecryptWrapper(buff, n - (n % 16));
        if (m != (n - (n % 16)))
        {
            printf("Error decrypt\n");
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}

void usage(const char *name)
{
    printf("The app can be used to upload file/directory to cloud.\n");
    printf("Usage:\n %s <-g|-o> [options..] <filename>\n", name);
    printf("File name argument is optional if create directory option is used.\n");
    printf("Options:\n");
    printf("-C | --create-dir <folder_name> Option to create directory. Will provide folder id.\n");
    printf("-d | --root-dir <folder_id>     Folder id to which the file/directory to upload.\n");
    printf("-g | --google-drive             Select google drive to take transaction.\n");
    printf("-o | --one-drive                Select one drive to take transaction.\n");
    printf("-v | --verbose                  Display detailed message.\n");
    printf("-f | --config                   Override default config file with custom config file.\n");
    printf("-r | --re-authen                Re-authentication once to move another cloud account.\n");
    printf("-h | --help                     Display usage instructions.\n");
}

int main(int argc, char *argv[])
{
    params_t param;

    Config *cfg = NULL;
    int i, ret;
    uint8_t cloud_type = 0;
    uint8_t debug = 0;

    memset(&param, 0, sizeof(params_t));
    if (argc == 1)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    for (i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-g") || !strcmp(argv[i], "--google-drive"))
        {
            cloud_type = 1; // is google drive
        }
        else if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--one-drive"))
        {
            cloud_type = 2; // is one drive
        }
        else if ((!strcmp(argv[i], "-C") || !strcmp(argv[i], "--create-dir")) && i + 1 < argc)
        {
            param.create_dir = argv[++i];
        }
        else if ((!strcmp(argv[i], "-d") || !strcmp(argv[i], "--root-dir")) && i + 1 < argc)
        {
            param.root_dir = argv[++i];
        }
        else if ((!strcmp(argv[i], "-f") || !strcmp(argv[i], "--config")) && i + 1 < argc)
        {
            param.conf_file = argv[++i];
        }
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
        {
            debug = 1;
        }
        else if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--re-authen"))
        {
            param.is_reauth = 1;
        }
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
        {
            usage(argv[0]);
            return EXIT_SUCCESS;
        }
        else
        {
            param.filepath = argv[i];
        }
    }

    if (!cloud_type)
    {
        printf("Did not pass cloud type\n");
        return EXIT_FAILURE;
    }

    if (param.conf_file == NULL)
    {
        printf("Config file did not passed\n");
        return EXIT_FAILURE;
    }
    if (-1 == access(param.conf_file, F_OK))
    {
        printf("Cannot access to %s\n", param.conf_file);
        return EXIT_FAILURE;
    }

    generate_secret_code(src_key, 12, param.key);
    config_decryption(param.conf_file, param.key, param.buff, sizeof(param.buff));
    param.config_encryption = config_encryption;

    cfg = ConfigNew();
    if (ConfigReadFromBuffer(param.buff, &cfg) != CONFIG_OK)
    {
        fprintf(stderr, "Read failed from buffer\n");
        return EXIT_FAILURE;
    }
    else
    {
        memset(param.buff, 0, sizeof(MAXBUF * 2));
    }

    switch (cloud_type)
    {
    case 1:
        ret = gdrive(cfg, &param, debug); break;
    case 2:
        ret = odrive(cfg, &param, debug); break;
    default:
        printf("Warning: undefined cloud type %d\n", cloud_type);
        ret = EXIT_FAILURE;
    }
    ConfigFree(cfg);

    return ret;
}
