#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#define MAXLEN 4

int main()
{
    FILE *skFile = fopen("test/secret.key", "rb");
    auto key = new_tfheGateBootstrappingSecretKeySet_fromFile(skFile);
    fclose(skFile);

    LweSample *ans = new_gate_bootstrapping_ciphertext_array(MAXLEN, key->params);

    FILE *answerData = fopen("test/answer.data", "rb");
    for (int i = 0; i < MAXLEN; i++)
        import_gate_bootstrapping_ciphertext_fromFile(answerData, &ans[i], key->params);
    fclose(answerData);

    FILE *dec = fopen("test/decrypt.txt", "wb");
    for (int i = 0; i < MAXLEN; i++){
        int bit = bootsSymDecrypt(&ans[i], key);
        fprintf(dec, "%d", bit);
    }
    fclose(dec);
    delete_gate_bootstrapping_ciphertext_array(MAXLEN, ans);
    delete_gate_bootstrapping_secret_keyset(key);

    return 0;
}