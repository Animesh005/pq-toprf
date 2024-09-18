#include <iostream>
#include <fstream>
#include <vector>
#include <math.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <tfhe/lwe-functions.h>
#include <tfhe/numeric_functions.h>
#include <tfhe/tlwe_functions.h>

void do_encrypt1(LweSample *cipher_text, int num){

    FILE *skFile = fopen("test/secret2.key", "rb");
    TFheGateBootstrappingSecretKeySet *key = new_tfheGateBootstrappingSecretKeySet_fromFile(skFile);
    fclose(skFile);
    FILE *paramFile = fopen("test/secret2.params", "rb");
    TFheGateBootstrappingParameterSet *params = new_tfheGateBootstrappingParameterSet_fromFile(paramFile);
    fclose(paramFile);
    std::cout << "num: " << num << "\n";
    std::cout << "N: " << params->in_out_params->n << "\n";   

    for (int i = 0; i < 32; i++)
    {
        bootsSymEncrypt(&cipher_text[i], modSwitchToTorus32((num >> i) & 1, 2), key);
        std::cout << cipher_text[i].a[0] << " "<< cipher_text[i].a[600] << "\n";
    }

}


void do_encrypt(LweSample **cipher_arr, int num){
    cipher_arr = new LweSample*[32];
    FILE *skFile = fopen("test/secret2.key", "rb");
    TFheGateBootstrappingSecretKeySet *key = new_tfheGateBootstrappingSecretKeySet_fromFile(skFile);
    fclose(skFile);
    FILE *paramFile = fopen("test/secret2.params", "rb");
    TFheGateBootstrappingParameterSet *params = new_tfheGateBootstrappingParameterSet_fromFile(paramFile);
    fclose(paramFile);
    std::cout << "num: " << num << "\n";
    std::cout << "N: " << params->in_out_params->n << "\n";
    for(int i = 0; i < 32; i++){
        cipher_arr[i] = new_LweSample(params->in_out_params);
        // tLweSymEncryptT(cipher_arr[i], modSwitchToTorus32((num >> i) & 1, 2), 0.001, key);
        bootsSymEncrypt(cipher_arr[i], modSwitchToTorus32((num >> i) & 1, 2), key);
        // std::cout << i << " bit: " << ((num >> i) & 1) << "\n";
        std::cout << cipher_arr[0]->a[0] << " "<< cipher_arr[i]->a[629] << "\n";
    }
}
void homomorphic_nand(LweSample **result, LweSample ***ciphertexts, int count){
    FILE *cloudKeyFile = fopen("test/cloud2.key", "rb");
    auto cloud_key = new_tfheGateBootstrappingCloudKeySet_fromFile(cloudKeyFile);
    fclose(cloudKeyFile);
    std::cout << "hi1\n";
    FILE *paramFile = fopen("test/secret2.params", "rb");
    TFheGateBootstrappingParameterSet *params = new_tfheGateBootstrappingParameterSet_fromFile(paramFile);
    fclose(paramFile);
    std::cout << "hi2\n";
    result = new LweSample*[32];
    for(int j = 0; j < 32; j++){
        std::cout << ciphertexts[0][j]->a[0] << " " << ciphertexts[0][j]->a[629] << "\n";
        result[j] = ciphertexts[0][j];
    }
    // std::cout << ciphertexts[0][1]->a[1023] << std::endl;
    // for(int k = 0; k < 32; k++){
    //     std::cout << result[k]->a[0] << " " << result[k]->a[629] << "\n";
    // }
    LweSample *tmp;
    // for(int i = 1; i < count; i++){
    //     for(int j = 0; j < 32; j++){
    //         // std::cout << "i: " << i << " j: " << j << "\n";
    //         bootsNAND(tmp, result[j], ciphertexts[i][j], cloud_key);
    //         result[j] = tmp;
    //     }
    // }
}
int do_decrypt(LweSample **result){
    FILE *skFile = fopen("test/secret2.key", "rb");
    auto key = new_tfheGateBootstrappingSecretKeySet_fromFile(skFile);
    fclose(skFile);
    int bit, ans;
    for(int i = 0; i < 32; i++){
        bit = bootsSymDecrypt(result[i], key);
        ans += (bit << i);
    }
    return ans;
}
int main(){
    std::vector<int32_t> numbers;
    int32_t number;
    std::ifstream inp_file("test/inputs.txt");
    while(inp_file >> number){
        numbers.push_back(number);
    }
    inp_file.close();
    double b;
    int input_count = numbers.size();
    std::cout << "Number of inputs is : " << input_count  << ". Inputs are: \n";
    for(auto &i : numbers){
        std::cout << i << " ";
    }
    std::cout << std::endl;
    // TLweParams *params;
    // TLweKey *key;
    // params = new_TLweParams(1024 * 1024, 1, 0.01, 0.2);
    // key = new_TLweKey(params);
    // tLweKeyGen(key);
    const int minimum_lambda = 120;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);
    uint32_t seed[] = { 100, 20032, 21341 };
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet *key = new_random_gate_bootstrapping_secret_keyset(params);
    FILE* secret_key = fopen("test/secret2.key", "wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);
    FILE* cloud_key = fopen("test/cloud2.key", "wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);
    FILE* secret_params = fopen("test/secret2.params", "wb");
    export_tfheGateBootstrappingParameterSet_toFile(secret_params, params);
    fclose(secret_params);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
    // LweSample ***ciphertexts = new LweSample**[input_count];
    // for(int i = 0; i < input_count; i++){
    //     ciphertexts[i] = new LweSample*[32];
    //     do_encrypt(ciphertexts[i], numbers[i]);
    //     for(int j = 0; j< 32; j++){
    //         std::cout << ciphertexts[i][j]->a[0] << " " << ciphertexts[i][j]->a[629] <<"\n";
    //     }
    // }
    // LweSample **result;

    LweSample *cipher1 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample *cipher2 = new_gate_bootstrapping_ciphertext_array(32, params);
    do_encrypt1(cipher1, 25);

    //do_encrypt(cipher1, 24);


    //homomorphic_nand(result, ciphertexts, input_count);
    // int answer = do_decrypt(result);
    // std::cout << answer << std::endl;
    return 0;
}