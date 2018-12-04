// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "encryptor.h"
#include <string.h>
#include "common.h"
#include "fileencryptor_t.h"
#include "TH/TH.h"
#include "THNN/THNN.h"
#include "EmptyParameters.h"

#define INIT 10
#define THRESHOLD    0.0
#define INPLACE      false
#define MP_ceil_mode false
#define VAL          0.0

void *state;
unsigned char *decrypted_image;
int d_image_size;

unsigned char *decrypted_network_parameters;
int d_param_size;

void initialize_image_and_params_file(int image_size, int params_size){
	decrypted_image = (unsigned char*)calloc(image_size+16, sizeof(unsigned char));
    if(decrypted_image!=NULL){
        ocall_print_string((char *)"Allocated memory for decrypted_image");
    }    
    d_image_size=0;
    

	decrypted_network_parameters = (unsigned char*)calloc(params_size+16, sizeof(unsigned char*));
    if(decrypted_network_parameters!=NULL){
        ocall_print_string((char *)"Allocated memory for decrypted_networkparams");
    }    
	d_param_size=0;
}

int predict_class(float *arr, int count){
    int max_index = 0;
    float max_val = arr[0];
    for(int i=1;i<count;i++){
        if(arr[i] > max_val){
            max_val = arr[i];
            max_index = i;
        }
    }
    return max_index;
}

int get_num_lines(unsigned char *network_parameters, int network_size){
    int res=0;
    for(int i=0;i<network_size;i++){
        if(network_parameters[i]=='\n'){
            res++;
        }
    }
    return res;
}


int find_index(unsigned char *s_arr, char delimiter){
    unsigned char *e;
    int index=-1;
    e = (unsigned char*)strchr((char *)s_arr, delimiter);
    if(e){
        index = (int)(e-s_arr);
    }
    return index;
}

int parse_array(unsigned char *s_arr, float*f_arr, int length, int f_arr_index){
    int start_index=0;
    int end_index=0;

    int starting_brace_index = find_index(s_arr, '{');
    start_index = starting_brace_index+1;
    int temp_index=0;
    while(end_index<length-2){
        int comma_index = find_index(s_arr+end_index, ',');
        if(comma_index==-1){
            comma_index = find_index(s_arr+end_index, '}');
        }
        end_index = end_index+comma_index-1;

        s_arr[end_index+1] = '\0';
        float val = atof((char *)(s_arr+start_index));//val_str);
        s_arr[end_index+1] = ',';
        f_arr[f_arr_index] = val;
        f_arr_index++;
        end_index+=2;
        start_index=end_index;
        temp_index++;
    }
    return f_arr_index;
}

double get_sum(float *arr, int size){
    double res=0;
    for(int i=0;i<size;i++){
        res+=arr[i];
    }
    return res;
}

void parse_network_parameters(unsigned char *network_parameters, int network_size){
	ocall_print_string("entered PARSE NETWORK PARAMETERS");
    int total_elements = 62006;
    float *f_arr = (float*)malloc(total_elements*sizeof(float));
    int old_f_arr_index=0;
    int new_f_arr_index=0;
    int num_lines = get_num_lines(network_parameters, network_size);
    int *parameters_lines_arr = (int*)calloc(num_lines, sizeof(int));
    int start_index=0;
    int end_index=0;
    int temp_index=0;
    while(end_index<=network_size){
        int next_line_index = find_index(network_parameters+end_index, '\n');
        if(next_line_index==-1){
            break;
        }
        end_index = end_index+next_line_index-1;

        int length = end_index-start_index+1;
        new_f_arr_index = parse_array(network_parameters+start_index,f_arr, length, old_f_arr_index);
        parameters_lines_arr[temp_index] = new_f_arr_index-old_f_arr_index;
        end_index+=2;
        start_index=end_index;
        old_f_arr_index = new_f_arr_index;
        temp_index++;
    }

    int offset=0;
memcpy(learned_0, f_arr+offset, parameters_lines_arr[0]*4);
offset+=parameters_lines_arr[0];
memcpy(learned_1, f_arr+offset, parameters_lines_arr[1]*4);
offset+=parameters_lines_arr[1];
memcpy(learned_2, f_arr+offset, parameters_lines_arr[2]*4);
offset+=parameters_lines_arr[2];
memcpy(learned_3, f_arr+offset, parameters_lines_arr[3]*4);
offset+=parameters_lines_arr[3];
memcpy(learned_4, f_arr+offset, parameters_lines_arr[4]*4);
offset+=parameters_lines_arr[4];
memcpy(learned_5, f_arr+offset, parameters_lines_arr[5]*4);
offset+=parameters_lines_arr[5];
memcpy(learned_6, f_arr+offset, parameters_lines_arr[6]*4);
offset+=parameters_lines_arr[6];
memcpy(learned_7, f_arr+offset, parameters_lines_arr[7]*4);
offset+=parameters_lines_arr[7];
memcpy(learned_8, f_arr+offset, parameters_lines_arr[8]*4);
offset+=parameters_lines_arr[8];
memcpy(learned_9, f_arr+offset, parameters_lines_arr[9]*4);
offset+=parameters_lines_arr[9];
ocall_print_string("Printing sum of f_arr");
ocall_print_double(get_sum(f_arr, total_elements));
free(f_arr);
}

int input_size=3072;

THFloatTensor *actual_input_1;
THFloatTensor *_11;
THFloatTensor *learned_0_weights_tensor;
THFloatTensor *learned_1_bias_tensor;
THFloatTensor *actual_input_1_f;
THFloatTensor *_12;
THFloatTensor *_13;
THLongTensor *_12_mp_indices;
THFloatTensor *_14;
THFloatTensor *learned_2_weights_tensor;
THFloatTensor *learned_3_bias_tensor;
THFloatTensor *_13_f;
THFloatTensor *_15;
THFloatTensor *_16;
THLongTensor *_15_mp_indices;
THFloatTensor *_17;
THFloatTensor *_18;
THFloatTensor *learned_4_weights_tensor;
THFloatTensor *learned_5_bias_tensor;
THFloatTensor *_17_add_buffer;
THFloatTensor *_19;
THFloatTensor *_20;
THFloatTensor *learned_6_weights_tensor;
THFloatTensor *learned_7_bias_tensor;
THFloatTensor *_19_add_buffer;
THFloatTensor *_21;
THFloatTensor *output_1;
THFloatTensor *learned_8_weights_tensor;
THFloatTensor *learned_9_bias_tensor;
THFloatTensor *_21_add_buffer;

void initialize_parameters(int batch_size, int network_size){
    ocall_print_string("ENTERED INITIALIZE PARAMETERS");
	ocall_print_string("d_param_size");
	ocall_print_int(d_param_size);
    parse_network_parameters(decrypted_network_parameters, network_size);
        //Input Tensor
        actual_input_1 = THFloatTensor_newWithSize1d(batch_size);
        if (actual_input_1->storage->data == NULL)
                ocall_error("Could not allocate memory for input_tensor");
        THFloatTensor_resize4d(actual_input_1, batch_size, 3, 32, 32);

        //Output Tensor for Layer 1
        _11 = THFloatTensor_newWithSize1d(batch_size);
        if (_11->storage->data == NULL)
                ocall_error("Could not allocate memory for output_tensor");
        THFloatTensor_resize4d(_11, batch_size, 6, 28, 28);

        //Conv weights tensor
        learned_0_weights_tensor = THFloatTensor_newWithSize1d(6);
        if (learned_0_weights_tensor->storage->data == NULL)
                ocall_error("Could not allocate memory for conv weights_tensor");
        THFloatTensor_resize4d(learned_0_weights_tensor, 6, 3, 5, 5);
        memcpy(learned_0_weights_tensor->storage->data, learned_0, 1800);
        ocall_print_double(get_sum(learned_0,450));
        //Conv bias tensor
        learned_1_bias_tensor = THFloatTensor_newWithSize1d(6);
        if (learned_1_bias_tensor->storage->data == NULL)
                ocall_error("Could not allocate memory for conv bias_tensor");
        memcpy(learned_1_bias_tensor->storage->data, learned_1, 24);

        //Conv _f tensor
        actual_input_1_f = THFloatTensor_newWithSize1d(INIT);
        if (actual_input_1_f->storage->data == NULL)
                ocall_error("Could not allocate memory for conv _f tensor");

        //Output Tensor for Layer 2
        _12 = THFloatTensor_newWithSize1d(batch_size);
        if (_12->storage->data == NULL)
                ocall_error("Could not allocate memory for output_tensor");
        THFloatTensor_resize4d(_12, batch_size, 6, 28, 28);

        //Output Tensor for Layer 3
        _13 = THFloatTensor_newWithSize1d(batch_size);
        if (_13->storage->data == NULL)
                ocall_error("Could not allocate memory for output_tensor");
        THFloatTensor_resize4d(_13, batch_size, 6, 14, 14);

        //MAXPOOL _mp_indices tesnor
        _12_mp_indices = THLongTensor_newWithSize1d(INIT);
        if (_12_mp_indices->storage->data == NULL)
                ocall_error("Could not allocate memory for mp_indices tensor");

        //Output Tensor for Layer 4
        _14 = THFloatTensor_newWithSize1d(batch_size);
        if (_14->storage->data == NULL)
                ocall_error("Could not allocate memory for output_tensor");
        THFloatTensor_resize4d(_14, batch_size, 16, 10, 10);

        //Conv weights tensor
        learned_2_weights_tensor = THFloatTensor_newWithSize1d(16);
        if (learned_2_weights_tensor->storage->data == NULL)
                ocall_error("Could not allocate memory for conv weights_tensor");
        THFloatTensor_resize4d(learned_2_weights_tensor, 16, 6, 5, 5);
        memcpy(learned_2_weights_tensor->storage->data, learned_2, 9600);

        //Conv bias tensor
        learned_3_bias_tensor = THFloatTensor_newWithSize1d(16);
        if (learned_3_bias_tensor->storage->data == NULL)
                ocall_error("Could not allocate memory for conv bias_tensor");
        memcpy(learned_3_bias_tensor->storage->data, learned_3, 64);

        //Conv _f tensor
        _13_f = THFloatTensor_newWithSize1d(INIT);
        if (_13_f->storage->data == NULL)
                ocall_error("Could not allocate memory for conv _f tensor");

        //Output Tensor for Layer 5
        _15 = THFloatTensor_newWithSize1d(batch_size);
        if (_15->storage->data == NULL)
                ocall_error("Could not allocate memory for output_tensor");
        THFloatTensor_resize4d(_15, batch_size, 16, 10, 10);

        //Output Tensor for Layer 6
        _16 = THFloatTensor_newWithSize1d(batch_size);
        if (_16->storage->data == NULL)
                ocall_error("Could not allocate memory for output_tensor");
        THFloatTensor_resize4d(_16, batch_size, 16, 5, 5);

        //MAXPOOL _mp_indices tesnor
        _15_mp_indices = THLongTensor_newWithSize1d(INIT);
        if (_15_mp_indices->storage->data == NULL)
                ocall_error("Could not allocate memory for mp_indices tensor");

        //Output Tensor for Layer 7
        _17 = THFloatTensor_newWithSize1d(batch_size);
        if (_17->storage->data == NULL)
                ocall_error("Could not allocate memory for output_tensor");
        THFloatTensor_resize4d(_17, batch_size, 400, 0, 0);

        //Output Tensor for Layer 8
        _18 = THFloatTensor_newWithSize1d(batch_size);
        if (_18->storage->data == NULL)
                ocall_error("Could not allocate memory for output_tensor");
        THFloatTensor_resize4d(_18, batch_size, 120, 0, 0);

        ///Linear weights tensor
        learned_4_weights_tensor = THFloatTensor_newWithSize1d(120);
        if (learned_4_weights_tensor->storage->data == NULL)
                ocall_error("Could not allocate memory for weights_tensor");
        THFloatTensor_resize2d(learned_4_weights_tensor, 120, 400);
        memcpy(learned_4_weights_tensor->storage->data, learned_4, 192000);

        //Linear bias tensor
        learned_5_bias_tensor = THFloatTensor_newWithSize1d(120);
        if (learned_5_bias_tensor->storage->data == NULL)
                ocall_error("Could not allocate memory for bias_tensor");
        memcpy(learned_5_bias_tensor->storage->data, learned_5, 480);

        //_add_buffer tensorfor linear layer
        _17_add_buffer = THFloatTensor_newWithSize1d(INIT);
        if (_17_add_buffer->storage->data == NULL)
                ocall_error("Could not allocate memory for add_buffer_tensor");

        //Output Tensor for Layer 9
        _19 = THFloatTensor_newWithSize1d(batch_size);
        if (_19->storage->data == NULL)
                ocall_error("Could not allocate memory for output_tensor");
        THFloatTensor_resize4d(_19, batch_size, 120, 0, 0);

        //Output Tensor for Layer 10
        _20 = THFloatTensor_newWithSize1d(batch_size);
        if (_20->storage->data == NULL)
                ocall_error("Could not allocate memory for output_tensor");
        THFloatTensor_resize4d(_20, batch_size, 84, 0, 0);

        ///Linear weights tensor
        learned_6_weights_tensor = THFloatTensor_newWithSize1d(84);
        if (learned_6_weights_tensor->storage->data == NULL)
                ocall_error("Could not allocate memory for weights_tensor");
        THFloatTensor_resize2d(learned_6_weights_tensor, 84, 120);
        memcpy(learned_6_weights_tensor->storage->data, learned_6, 40320);

        //Linear bias tensor
        learned_7_bias_tensor = THFloatTensor_newWithSize1d(84);
        if (learned_7_bias_tensor->storage->data == NULL)
                ocall_error("Could not allocate memory for bias_tensor");
        memcpy(learned_7_bias_tensor->storage->data, learned_7, 336);

        //_add_buffer tensorfor linear layer
        _19_add_buffer = THFloatTensor_newWithSize1d(INIT);
        if (_19_add_buffer->storage->data == NULL)
                ocall_error("Could not allocate memory for add_buffer_tensor");

        //Output Tensor for Layer 11
        _21 = THFloatTensor_newWithSize1d(batch_size);
        if (_21->storage->data == NULL)
                ocall_error("Could not allocate memory for output_tensor");
        THFloatTensor_resize4d(_21, batch_size, 84, 0, 0);

        //Output Tensor for Layer 12
        output_1 = THFloatTensor_newWithSize1d(batch_size);
        if (output_1->storage->data == NULL)
                ocall_error("Could not allocate memory for output_tensor");
        THFloatTensor_resize4d(output_1, batch_size, 10, 0, 0);

        ///Linear weights tensor
        learned_8_weights_tensor = THFloatTensor_newWithSize1d(10);
        if (learned_8_weights_tensor->storage->data == NULL)
                ocall_error("Could not allocate memory for weights_tensor");
        THFloatTensor_resize2d(learned_8_weights_tensor, 10, 84);
        memcpy(learned_8_weights_tensor->storage->data, learned_8, 3360);

        //Linear bias tensor
        learned_9_bias_tensor = THFloatTensor_newWithSize1d(10);
        if (learned_9_bias_tensor->storage->data == NULL)
                ocall_error("Could not allocate memory for bias_tensor");
        memcpy(learned_9_bias_tensor->storage->data, learned_9, 40);

        //_add_buffer tensorfor linear layer
        _21_add_buffer = THFloatTensor_newWithSize1d(INIT);
        if (_21_add_buffer->storage->data == NULL)
                ocall_error("Could not allocate memory for add_buffer_tensor");

}

void inference_engine(int batch_size, int *res){
            for(int j = 0;j < batch_size;j++){
                for (int i = 0;i < input_size/3;i++)
                        actual_input_1->storage->data[i+j*input_size] = (decrypted_image[i+j*input_size]*1.0/255.0 - 0.4914)/0.2023; //casting char to float
                for (int i = input_size/3;i < input_size*2/3;i++)
                        actual_input_1->storage->data[i+j*input_size] = (decrypted_image[i+j*input_size]*1.0/255.0 - 0.4822)/0.1994; //casting char to float
                for (int i = input_size*2/3;i < input_size;i++)
                        actual_input_1->storage->data[i+j*input_size] = (decrypted_image[i+j*input_size]*1.0/255.0 - 0.4465)/0.2010; //casting char to float

            }
            ocall_print_double(get_sum(actual_input_1->storage->data, actual_input_1->storage->size));
ocall_print_double(get_sum(learned_0_weights_tensor->storage->data, learned_0_weights_tensor->storage->size));
                    //Convolution layer
        THNN_FloatSpatialConvolutionMM_updateOutput(state, actual_input_1, _11, learned_0_weights_tensor, learned_1_bias_tensor, actual_input_1_f, NULL, 5, 5, 1, 1, 0, 0);
// ocall_print_double(get_sum(_11->storage->data, _11->storage->size));
// ocall_print_double(get_sum(learned_1_bias_tensor->storage->data, learned_1_bias_tensor->storage->size));

        //RELU layer
        THNN_FloatThreshold_updateOutput(state, _11, _12, THRESHOLD, VAL, INPLACE);
// ocall_print_double(get_sum(_12->storage->data, _12->storage->size));
        //MAXPOOL layer
        THNN_FloatSpatialMaxPooling_updateOutput(state, _12, _13, _12_mp_indices, 2, 2, 2, 2, 0, 0, MP_ceil_mode);
// ocall_print_double(get_sum(_13->storage->data, _13->storage->size));
        //Convolution layer
        THNN_FloatSpatialConvolutionMM_updateOutput(state, _13, _14, learned_2_weights_tensor, learned_3_bias_tensor, _13_f, NULL, 5, 5, 1, 1, 0, 0);

        //RELU layer
        THNN_FloatThreshold_updateOutput(state, _14, _15, THRESHOLD, VAL, INPLACE);

        //MAXPOOL layer
        THNN_FloatSpatialMaxPooling_updateOutput(state, _15, _16, _15_mp_indices, 2, 2, 2, 2, 0, 0, MP_ceil_mode);

        //Flatten to change from conv to linear layers; Assuming reshape == flatten (not always true -- TBD!)
        THFloatTensor_resize2d(_16, batch_size, 400);
        _17 = _16;//TBD: skip thi

        //Linear layer
        THNN_FloatLinear_updateOutput(state, _17, _18, learned_4_weights_tensor, learned_5_bias_tensor, _17_add_buffer);

        //RELU layer
        THNN_FloatThreshold_updateOutput(state, _18, _19, THRESHOLD, VAL, INPLACE);

        //Linear layer
        THNN_FloatLinear_updateOutput(state, _19, _20, learned_6_weights_tensor, learned_7_bias_tensor, _19_add_buffer);

        //RELU layer
        THNN_FloatThreshold_updateOutput(state, _20, _21, THRESHOLD, VAL, INPLACE);

        //Linear layer
        THNN_FloatLinear_updateOutput(state, _21, output_1, learned_8_weights_tensor, learned_9_bias_tensor, _21_add_buffer);

        for(int j = 0;j < batch_size;j++)
                res[j] = predict_class(output_1->storage->data+j*10, 10);

}


ecall_dispatcher::ecall_dispatcher() : m_encrypt(true), m_header(NULL)
{
    unsigned char iv[IV_SIZE] = {0xb2,
                                 0x4b,
                                 0xf2,
                                 0xf7,
                                 0x7a,
                                 0xc5,
                                 0xec,
                                 0x0c,
                                 0x5e,
                                 0x1f,
                                 0x4d,
                                 0xc1,
                                 0xae,
                                 0x46,
                                 0x5e,
                                 0x75};
    memcpy(m_original_iv, iv, IV_SIZE);
}

int ecall_dispatcher::initialize(
    bool encrypt,
    const char* password,
    size_t password_len,
    encryption_header_t* header)
{
    int ret = 0;
    TRACE_ENCLAVE(
        "ecall_dispatcher::initialize : %s request",
        encrypt ? "encrypting" : "decrypting");

    m_encrypt = encrypt;

    ret = process_encryption_header(encrypt, password, password_len, header);
    if (ret != 0)
    {
        TRACE_ENCLAVE("process_encryption_header failed with %d", ret);
        goto exit;
    }

    // initialize aes context
    mbedtls_aes_init(&m_aescontext);

    // set aes key
    if (encrypt)
        ret = mbedtls_aes_setkey_enc(
            &m_aescontext, m_encryption_key, ENCRYPTION_KEY_SIZE);
    else
        ret = mbedtls_aes_setkey_dec(
            &m_aescontext, m_encryption_key, ENCRYPTION_KEY_SIZE);

    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_setkey_dec failed with %d", ret);
        goto exit;
    }
    // init iv
    memcpy(m_operating_iv, m_original_iv, IV_SIZE);
exit:
    return ret;
}

int ecall_dispatcher::encrypt_block(
    bool encrypt,
    unsigned char* input_buf,
    unsigned char* output_buf,
    size_t size,
    int type)
{
    int ret = 0;
    ret = mbedtls_aes_crypt_cbc(
        &m_aescontext,
        encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
        size,           // input data length in bytes,
        m_operating_iv, // Initialization vector (updated after use)
        input_buf,
        output_buf);
	if(!encrypt){
            // ocall_print_int(d_image_size);
            // if(decrypted_image!=NULL){
            //     ocall_print_int(121212);
            //     ocall_print_int(size);
            //     ocall_print_int(type);
            // }
        	if(type==0){
    			for(int i=0;i<size;i++){
    				decrypted_image[d_image_size] = output_buf[i];
    				d_image_size++;
    			}
        	}
        	else{
                    for(int i=0;i<size;i++){
       	        		decrypted_network_parameters[d_param_size] = output_buf[i];
                		d_param_size++;
            		}
        	}
		//ocall_print_string((char *)output_buf);
		// ocall_print_int(size);
	}
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_crypt_cbc failed with %d", ret);
    }
    return ret;
}

void ecall_dispatcher::close()
{
    if (m_encrypt)
    {
        oe_host_free(m_header);
        m_header = NULL;
    }

    // free aes context
    mbedtls_aes_free(&m_aescontext);
    TRACE_ENCLAVE("ecall_dispatcher::close");
}
