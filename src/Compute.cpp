#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#define MAXLEN 4

void Compute(LweSample *result, const LweSample *input, const int nbits, const TFheGateBootstrappingCloudKeySet *bk)
{
    for (int i = 0; i < nbits; i++){
        bootsAND(&result[i], &input[i], &input[nbits - i - 1], bk);
    }
}

int main()
{
    FILE *cloudKeyFile = fopen("test/cloud.key", "rb");
    auto cloud_key = new_tfheGateBootstrappingCloudKeySet_fromFile(cloudKeyFile);
    fclose(cloudKeyFile);

    LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(MAXLEN, cloud_key->params);
    FILE *cloud_data = fopen("test/cloud.data", "rb");
    for (int i = 0; i < MAXLEN; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext[i], cloud_key->params);
    fclose(cloud_data);

    LweSample *result = new_gate_bootstrapping_ciphertext_array(MAXLEN, cloud_key->params);
    Compute(result, ciphertext, MAXLEN, cloud_key);

    FILE *answer_data = fopen("test/answer.data", "wb");
    for (int i = 0; i < MAXLEN; i++)
        export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], cloud_key->params);
    fclose(answer_data);


    delete_gate_bootstrapping_ciphertext_array(MAXLEN, result);
    delete_gate_bootstrapping_ciphertext_array(MAXLEN, ciphertext);
    delete_gate_bootstrapping_cloud_keyset(cloud_key);

    return 0;

}