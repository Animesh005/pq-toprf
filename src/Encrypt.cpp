#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

#define MAXLEN 4

int main()
{
    // Read from file as binary and encrypt
    FILE *skFile = fopen("test/secret.key", "rb");
    auto key = new_tfheGateBootstrappingSecretKeySet_fromFile(skFile);
    fclose(skFile);

    FILE *plaintext = fopen("test/plain.txt", "rb");
    int len;
    char buff;
    for (len = 0; len < MAXLEN && !feof(plaintext); len++){
        fscanf(plaintext, "%c", &buff);
    }

    rewind(plaintext);

    FILE *paramFile = fopen("test/secret.params", "rb");
    auto params = new_tfheGateBootstrappingParameterSet_fromFile(paramFile);
    fclose(paramFile);    

    LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(MAXLEN * 8, params);
    for (int i = 0; i < MAXLEN; i++){
        if (i < len)
            fscanf(plaintext, "%c", &buff);
        else
            buff = 0;
        for (int j = 0; j < 8; j++){
            std::cout << ((buff >> j) & 1);
            bootsSymEncrypt(&ciphertext[8 * i + j], (buff >> j) & 1, key);
        }
        std::cout << "\n";
    }

    fclose(plaintext);

    FILE *cloud_data = fopen("test/cloud.data", "wb");
    for (int i = 0; i < MAXLEN; i++){
        for (int j = 0; j < 8; j++){
            export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[8 * i + j], params);
        }
    }
    fclose(cloud_data);

    delete_gate_bootstrapping_ciphertext_array(len * 8, ciphertext);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}