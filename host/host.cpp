// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <iostream>
#include <iterator>
#include <vector>
#include "../shared.h"

#include "fileencryptor_u.h"

using namespace std;

#define CIPHER_BLOCK_SIZE 16
#define DATA_BLOCK_SIZE 256
#define ENCRYPT_OPERATION true
#define DECRYPT_OPERATION false
#define TYPE_IMAGE 0
#define TYPE_PARAMETERS 1
#define ENCRYPTION_ENABLED 0
#define ENCRYPTED_PARAMETERS_PATH "/home/karan/samples/torchtestv3/enc/Parameters.h.enc"
#define PARAMETERS_PATH "/home/karan/samples/torchtestv3/enc/Parameters.h"

oe_enclave_t* enclave = NULL;

void ocall_print_string(char *msg){
	printf("%s\n", msg);
}

void ocall_print_int(int val){
	printf("%d\n", val);
}

void ocall_print_double(double val){
    printf("Ocall_print_double: %lf\n", val);
}

void ocall_error(char *msg){
    printf("%s\n", msg);
}
bool check_simulate_opt(int* argc, const char* argv[])
{
    for (int i = 0; i < *argc; i++)
    {
        if (strcmp(argv[i], "--simulate") == 0)
        {
            cout << "Running in simulation mode" << endl;
            memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
            (*argc)--;
            return true;
        }
    }
    return false;
}

// Dump Encryption header
void dump_header(encryption_header_t* _header)
{
    cout << "--------- Dumping header -------------\n";
    cout << "Host: fileDataSize = " << _header->file_data_size << endl;

    cout << "Host: password digest:\n";
    for (int i = 0; i < HASH_VALUE_SIZE_IN_BYTES; i++)
    {
        cout << "Host: digest[" << i << "]" << std::hex
             << (unsigned int)(_header->digest[i]) << endl;
    }

    cout << "Host: encryption key" << endl;
    for (int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
    {
        cout << "Host: key[" << i << "]=" << std::hex
             << (unsigned int)(_header->encrypted_key[i]) << endl;
    }
}

// get the file size
int get_file_size(FILE* file, size_t* _file_size)
{
    int ret = 0;
    long int oldpos = 0;

    oldpos = ftell(file);
    ret = fseek(file, 0L, SEEK_END);
    if (ret != 0)
        goto exit;

    *_file_size = (size_t)ftell(file);
    fseek(file, oldpos, SEEK_SET);
exit:
    return ret;
}

// Compare file1 and file2: return 0 if the first file1.size bytes of the file2
// is equal to file1's contents  Otherwise it returns 1
int compare_2_files(const char* first_file, const char* second_file)
{
    int ret = 0;
    std::ifstream f1(first_file, std::ios::binary);
    std::ifstream f2(second_file, std::ios::binary);
    std::vector<uint8_t> f1_data_bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f1), std::istreambuf_iterator<char>());
    std::vector<uint8_t> f2_data_bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f2), std::istreambuf_iterator<char>());
    std::vector<uint8_t>::iterator f1iterator = f1_data_bytes.begin();
    std::vector<uint8_t>::iterator f2iterator = f2_data_bytes.begin();

    // compare files
    for (; f1iterator != f1_data_bytes.end() - 1; ++f1iterator, ++f2iterator)
    {
        if (!(*f1iterator == *f2iterator))
        {
            ret = 1;
            break;
        }
    }
    cout << "Host: two files are " << ((ret == 0) ? "equal" : "not equal")
         << endl;
    return ret;
}

int encrypt_file(
    bool encrypt,
    const char* password,
    const char* input_file,
    const char* output_file, int type)
{
    oe_result_t result;
    int ret = 0;
    FILE* src_file = NULL;
    FILE* dest_file = NULL;
    unsigned char* r_buffer = NULL;
    unsigned char* w_buffer = NULL;
    size_t bytes_read;
    size_t bytes_written;
    size_t src_file_size = 0;
    size_t src_data_size = 0;
    size_t leftover_bytes = 0;
    size_t bytes_left = 0;
    size_t requested_read_size = 0;
    encryption_header_t header;

    // allocate read/write buffers
    r_buffer = new unsigned char[DATA_BLOCK_SIZE];
    if (r_buffer == NULL)
    {
        ret = 1;
        goto exit;
    }

    w_buffer = new unsigned char[DATA_BLOCK_SIZE];
    if (w_buffer == NULL)
    {
        cerr << "Host: w_buffer allocation error" << endl;
        ret = 1;
        goto exit;
    }

    // open source and dest files
    src_file = fopen(input_file, "r");
    if (!src_file)
    {
        cout << "Host: fopen " << input_file << " failed." << endl;
        ret = 1;
        goto exit;
    }

    ret = get_file_size(src_file, &src_file_size);
    if (ret != 0)
    {
        ret = 1;
        goto exit;
    }
    src_data_size = src_file_size;
    dest_file = fopen(output_file, "w");
    if (!dest_file)
    {
        cerr << "Host: fopen " << output_file << " failed." << endl;
        ret = 1;
        goto exit;
    }

    // For decryption, we want to read encryption header data into the header
    // structure before calling initialize_encryptor
    if (!encrypt)
    {
        bytes_read = fread(&header, 1, sizeof(header), src_file);
        if (bytes_read != sizeof(header))
        {
            cerr << "Host: read header failed." << endl;
            ret = 1;
            goto exit;
        }
        src_data_size = src_file_size - sizeof(header);
    }

    // Initialize the encryptor inside the enclave
    // Parameters: encrypt: a bool value to set the encryptor mode, true for
    // encryption and false for decryption
    // password is provided for encryption key used inside the encryptor. Upon
    // return, _header will be filled with encryption key information for
    // encryption operation. In the case of decryption, the caller provides
    // header information from a previously encrypted file
    result = initialize_encryptor(
        enclave, &ret, encrypt, password, strlen(password), &header);
    if (result != OE_OK)
    {
        ret = 1;
        goto exit;
    }
    if (ret != 0)
    {
        goto exit;
    }

    // For encryption, on return from initialize_encryptor call, the header will
    // have encryption information. Write this header to the output file.
    if (encrypt)
    {
        header.file_data_size = src_file_size;
        bytes_written = fwrite(&header, 1, sizeof(header), dest_file);
        if (bytes_written != sizeof(header))
        {
            cerr << "Host: writting header failed. bytes_written = "
                 << bytes_written << " sizeof(header)=" << sizeof(header)
                 << endl;
            ret = 1;
            goto exit;
        }
    }

    leftover_bytes = src_data_size % CIPHER_BLOCK_SIZE;

    cout << "Host: leftover_bytes " << leftover_bytes << endl;

    // Encrypt each block in the source file and write to the dest_file. Process
    // all the blocks except the last one if its size is not a multiple of
    // CIPHER_BLOCK_SIZE when padding is needed
    bytes_left = src_data_size;

    if (leftover_bytes)
    {
        bytes_left = src_data_size - leftover_bytes;
    }
    requested_read_size = DATA_BLOCK_SIZE;
    cout << "Host: start " << (encrypt ? "encrypting" : "decrypting") << endl;

    // It loops through DATA_BLOCK_SIZE blocks one at a time then followed by
    // processing the last remaining multiple of CIPHER_BLOCK_SIZE blocks. This
    // loop makes sure all the data is processed except leftover_bytes bytes in
    // the end.
    while (
        (bytes_read = fread(
             r_buffer, sizeof(unsigned char), requested_read_size, src_file)) &&
        bytes_read > 0)
    {
        // Request for the enclave to encrypt or decrypt _input_buffer. The
        // block size (bytes_read), needs to be a multiple of CIPHER_BLOCK_SIZE.
        // In this sample, DATA_BLOCK_SIZE is used except the last block, which
        // will have to pad it to be a multiple of CIPHER_BLOCK_SIZE.
        // printf("11111111\n");
        result = encrypt_block(
            enclave, &ret, encrypt, r_buffer, w_buffer, bytes_read, type);
        if (result != OE_OK)
        {
            cerr << "encrypt_block error 1" << endl;
            ret = 1;
            goto exit;
        }
        if (ret != 0)
        {
            cerr << "encrypt_block error 1" << endl;
            goto exit;
        }

        if ((bytes_written = fwrite(
                 w_buffer, sizeof(unsigned char), bytes_read, dest_file)) !=
            bytes_read)
        {
            cerr << "Host: fwrite error  " << output_file << endl;
            ret = 1;
            goto exit;
        }
        bytes_left -= requested_read_size;
        if (bytes_left == 0)
            break;
        if (bytes_left < DATA_BLOCK_SIZE)
        {
            requested_read_size = bytes_left;
        }
    }

    if (encrypt)
    {
        // The CBC mode for AES assumes that we provide data in blocks of
        // CIPHER_BLOCK_SIZE bytes. This sample uses PKCS#5 padding. Pad the
        // whole CIPHER_BLOCK_SIZE block if leftover_bytes is zero. Pad the
        // (CIPHER_BLOCK_SIZE - leftover_bytes) bytes if leftover_bytes is
        // non-zero.
        size_t padded_byte_count = 0;
        unsigned char plaintext_padding_buf[CIPHER_BLOCK_SIZE];
        unsigned char ciphertext_padding_buf[CIPHER_BLOCK_SIZE];

        memset(ciphertext_padding_buf, 0, CIPHER_BLOCK_SIZE);
        memset(plaintext_padding_buf, 0, CIPHER_BLOCK_SIZE);

        if (leftover_bytes == 0)
            padded_byte_count = CIPHER_BLOCK_SIZE;
        else
            padded_byte_count = CIPHER_BLOCK_SIZE - leftover_bytes;

        cout << "Host: Working the last block" << endl;
        cout << "Host: padded_byte_count " << padded_byte_count << endl;
        cout << "Host: leftover_bytes " << leftover_bytes << endl;

        bytes_read = fread(
            plaintext_padding_buf,
            sizeof(unsigned char),
            leftover_bytes,
            src_file);
        if (bytes_read != leftover_bytes)
            goto exit;

        // PKCS5 Padding
        memset(
            (void*)(plaintext_padding_buf + leftover_bytes),
            padded_byte_count,
            padded_byte_count);

        result = encrypt_block(
            enclave,
            &ret,
            encrypt,
            plaintext_padding_buf,
            ciphertext_padding_buf,
            CIPHER_BLOCK_SIZE, type);
        if (result != OE_OK)
        {
            ret = 1;
            goto exit;
        }
        if (ret != 0)
        {
            goto exit;
        }

        bytes_written = fwrite(
            ciphertext_padding_buf,
            sizeof(unsigned char),
            CIPHER_BLOCK_SIZE,
            dest_file);
        if (bytes_written != CIPHER_BLOCK_SIZE)
            goto exit;
    }

    cout << "Host: done  " << (encrypt ? "encrypting" : "decrypting") << endl;

    // close files
    fclose(src_file);
    fclose(dest_file);

exit:
    delete[] r_buffer;
    delete[] w_buffer;
    cout << "Host: called close_encryptor" << endl;

    result = close_encryptor(enclave);
    if (result != OE_OK)
    {
        ret = 1;
    }
    return ret;
}

int read_parameters_file(unsigned char **network_parameters, char *network_name){
    char *parameters_path;
    if(ENCRYPTION_ENABLED){
        parameters_path = (char *)ENCRYPTED_PARAMETERS_PATH;
    }
    else{
        parameters_path = (char *)PARAMETERS_PATH;
    }

        //unsigned char * buffer = *network_parameters;
        int length;
        FILE * f = fopen (parameters_path, "rb");

        if (f){
                fseek (f, 0, SEEK_END);
                length = ftell (f);
                fseek (f, 0, SEEK_SET);
                *network_parameters = (unsigned char*) malloc (length*sizeof(unsigned char));
                if (*network_parameters){
                        fread (*network_parameters, 1, length, f);
                }
                else{
                        ocall_error((char *)"Couldnt allocate memory for parameters file");
                }
                fclose (f);
        }
        else{
                ocall_error((char *)"Couldn't open file");
        }
        //*network_parameters = buffer;
        return length;
}

int get_file_size(char *path){
    FILE * f = fopen (path, "rb");
    fseek (f, 0, SEEK_END);
    int length = ftell (f);
    fclose (f);
    return length;
}

int main(int argc, const char* argv[])
{
    int network_size;
    unsigned char *network_parameters;
    int *res;
    int file_count;
    char * plain_parameters_file = (char *)"/home/karan/samples/torchtestv3/enc/Parameters.h";
    char * encrypted_parameters_file = (char *)"/home/karan/samples/torchtestv3/enc/Parameters.h.enc";
    char * decrypted_parameters_file = (char *)"/home/karan/samples/torchtestv3/enc/Parameters.h.dec";

    // char * plain_parameters_file = (char *)"/home/karan/samples/torchtestv3/enc/Parameters1.h";
    // char * encrypted_parameters_file = (char *)"/home/karan/samples/torchtestv3/enc/Parameters1.h.enc";
    // char * decrypted_parameters_file = (char *)"/home/karan/samples/torchtestv3/enc/Parameters1.h.dec";

    char * plain_image_file = (char *)"/home/karan/samples/torchtestv3/airplane1.rgb";
    char * encrypted_image_file = (char *)"/home/karan/samples/torchtestv3/airplane1.rgb.enc";
    char * decrypted_image_file = (char *)"/home/karan/samples/torchtestv3/airplane1.rgb.dec";

    // START OF READING PARAMETERS AND INPUT

    // END OF READING PARAMETERS AND INPUT
    oe_result_t result;
    int ret = 0;
    const char* input_file = argv[1];
    const char* encrypted_file = "./out.encrypted";
    const char* decrypted_file = "./out.decrypted";
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

    if (check_simulate_opt(&argc, argv))
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    cout << "Host: enter main" << endl;
    if (argc != 3)
    {
        cerr << "Usage: " << argv[0]
             << " testfile enclave_image_path [ --simulate  ]" << endl;
        return 1;
    }

    cout << "Host: create enclave for image:" << argv[2] << endl;
    result = oe_create_fileencryptor_enclave(
        argv[2], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        cerr << "oe_create_fileencryptor_enclave() failed with " << argv[0]
             << " " << result << endl;
        ret = 1;
        goto exit;
    }

    initialize_image_and_params_file(enclave, get_file_size(plain_image_file), get_file_size(plain_parameters_file));

    // encrypt parameters file
    cout << "Host: encrypting parameters file:" << plain_parameters_file
         << " -> file:" << encrypted_parameters_file << endl;
    ret = encrypt_file(
        ENCRYPT_OPERATION, "anyPasswordYouLike", plain_parameters_file, encrypted_parameters_file, TYPE_PARAMETERS);
    if (ret != 0)
    {
        cerr << "Host: processFile(ENCRYPT_OPERATION) failed with " << ret
             << endl;
        goto exit;
    }

    //Check parameters encryption
    cout << "Host: compared file:" << encrypted_parameters_file
         << " to file:" << plain_parameters_file << endl;
    ret = compare_2_files(plain_parameters_file, encrypted_parameters_file);
    if (ret == 0)
    {
        cerr << "Host: checking failed! " << plain_parameters_file
             << "'s contents are not supposed to be same as " << encrypted_parameters_file
             << endl;
        goto exit;
    }
    cout << "Host: " << plain_parameters_file << " is NOT equal to " << encrypted_parameters_file
         << "as expected" << endl;
    cout << "Host: encryption was done successfully" << endl;

    // Decrypt parameters file
    cout << "Host: decrypting file:" << encrypted_parameters_file
         << " to file:" << decrypted_parameters_file << endl;

    ret = encrypt_file(
        DECRYPT_OPERATION,
        "anyPasswordYouLike",
        encrypted_parameters_file,
        decrypted_parameters_file, TYPE_PARAMETERS);
    if (ret != 0)
    {
        cerr << "Host: processFile(DECRYPT_OPERATION) failed with " << ret
             << endl;
        goto exit;
    }

    // Check parameters decryption
    cout << "Host: compared file:" << plain_parameters_file
         << " to file:" << decrypted_parameters_file << endl;
    ret = compare_2_files(plain_parameters_file, decrypted_parameters_file);
    if (ret != 0)
    {
        cerr << "Host: checking failed! " << plain_parameters_file
             << "'s is supposed to be same as " << decrypted_parameters_file << endl;
        goto exit;
    }
    cout << "Host: " << plain_parameters_file << " is equal to " << decrypted_parameters_file << endl;

    // encrypt image file
    cout << "Host: encrypting image file:" << input_file
         << " -> file:" << encrypted_file << endl;
    ret = encrypt_file(
        ENCRYPT_OPERATION, "anyPasswordYouLike", plain_image_file, encrypted_image_file, TYPE_IMAGE);
    if (ret != 0)
    {
        cerr << "Host: processFile(ENCRYPT_OPERATION) failed with " << ret
             << endl;
        goto exit;
    }

    //Check image encryption    
    cout << "Host: compared file:" << encrypted_image_file
         << " to file:" << plain_image_file << endl;
    ret = compare_2_files(plain_image_file, encrypted_image_file);
    if (ret == 0)
    {
        cerr << "Host: checking failed! " << plain_image_file
             << "'s contents are not supposed to be same as " << encrypted_image_file
             << endl;
        goto exit;
    }
    cout << "Host: " << plain_image_file << " is NOT equal to " << encrypted_image_file
         << "as expected" << endl;
    cout << "Host: encryption was done successfully" << endl;

    // Decrypt image file
    ret = encrypt_file(
        DECRYPT_OPERATION,
        "anyPasswordYouLike",
        encrypted_image_file,
        decrypted_image_file, TYPE_IMAGE);
    if (ret != 0)
    {
        cerr << "Host: processFile(DECRYPT_OPERATION) failed with " << ret
             << endl;
        goto exit;
    }

    // Check image decryption
    cout << "Host: compared file:" << plain_image_file
         << " to file:" << decrypted_image_file << endl;
    ret = compare_2_files(plain_image_file, decrypted_image_file);
    if (ret != 0)
    {
        cerr << "Host: checking failed! " << plain_image_file
             << "'s is supposed to be same as " << decrypted_image_file << endl;
        goto exit;
    }
    cout << "Host: " << plain_image_file << " is equal to " << decrypted_image_file << endl;

	file_count = 1;
	initialize_parameters(enclave, file_count, get_file_size(plain_parameters_file));
	res = (int *)malloc(file_count*sizeof(int));
	inference_engine(enclave, file_count, res);
	for(int i=0;i<file_count;i++){
		printf("Res: %d\n", res[i]);
	}

exit:
    cout << "Host: terminate the enclave" << endl;
    cout << "Host: Sample completed successfully." << endl;
    oe_terminate_enclave(enclave);
    return ret;
}
