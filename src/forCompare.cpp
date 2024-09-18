#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <time.h>

#define MAXLEN 4


void Compute(LweSample *result, const LweSample *input1, const LweSample *input2, const int nbits, const TFheGateBootstrappingCloudKeySet *bk)
{
    for (int i = 0; i < nbits; i++){
        bootsXOR(&result[i], &input1[i], &input2[i], bk);
    }
}

void HalfAdder(LweSample *sum, LweSample *carrybit, LweSample *input1, LweSample *input2, const int nbits, const TFheGateBootstrappingCloudKeySet *bk)
{

    for (int i = 0; i < nbits; i++){
        bootsXOR(&sum[i], &input1[i], &input2[i], bk);
        bootsAND(&carrybit[i], &input1[i], &input2[i], bk);
    }
}

void FullAdder(LweSample *sum2, LweSample *carrybit, LweSample *input1, LweSample *input2, const int nbits, const TFheGateBootstrappingCloudKeySet *bk)
{
    LweSample *sum1 = new_gate_bootstrapping_ciphertext_array(32, bk->params);
    LweSample *carry1 = new_gate_bootstrapping_ciphertext_array(32, bk->params);
    LweSample *carry2 = new_gate_bootstrapping_ciphertext_array(32, bk->params);

    for (int i = nbits-1; i >= 0; i--){
        // half adder 1
        bootsXOR(&sum1[i], &input1[i], &input2[i], bk);
        bootsAND(&carry1[i], &input1[i], &input2[i], bk);

        // half adder 2
        bootsXOR(&sum2[i], &sum1[i], &carrybit[i], bk);
        bootsAND(&carry2[i], &sum1[i], &carrybit[i], bk);

        // final carry
        if(i != 0)
        bootsOR(&carrybit[i-1], &carry1[i], &carry2[i], bk);

    }
}



void onesComplemet(LweSample *result, const LweSample *input1, const int nbits, const TFheGateBootstrappingCloudKeySet *bk)
{
    for (int i = 0; i < nbits; i++){
        bootsNOT(&result[i], &input1[i], bk);
        //bootsXOR(&result[i], &input1[i], &input2[i], bk);
    }
}







int main()
{
    clock_t start1, end1;
    start1 = clock();

    const int minimum_lambda = 110;
    auto params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    uint32_t seed[] = { 100, 20032, 21341 };
    tfhe_random_generator_setSeed(seed, 3);

    auto key = new_random_gate_bootstrapping_secret_keyset(params);

    FILE* secret_key = fopen("test/secret.key", "wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    FILE* cloud_key = fopen("test/cloud.key", "wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    FILE* secret_params = fopen("test/secret.params", "wb");
    export_tfheGateBootstrappingParameterSet_toFile(secret_params, params);
    fclose(secret_params);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);


    // Now encrypt the message....

    FILE *skFile = fopen("test/secret.key", "rb");
    auto key_ = new_tfheGateBootstrappingSecretKeySet_fromFile(skFile);
    fclose(skFile);

    FILE *plaintext1 = fopen("test/plain1.txt", "rb");
    int len;
    int buff1;
    fscanf(plaintext1, "%d", &buff1);

    //printf("\n%c",buff1);

    rewind(plaintext1);

    FILE *paramFile = fopen("test/secret.params", "rb");
    auto params_ = new_tfheGateBootstrappingParameterSet_fromFile(paramFile);
    fclose(paramFile);    

    LweSample *ciphertext1 = new_gate_bootstrapping_ciphertext_array(32, params_);
    for (int i = 0; i < 32; i++){
        //std::cout << ((buff1 >> i) & 1);
        bootsSymEncrypt(&ciphertext1[31-i], (buff1 >> i) & 1, key_);
        //std::cout << "\n";
    }

    fclose(plaintext1);

    FILE *cloud_data1 = fopen("test/cloud1.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(cloud_data1, &ciphertext1[i], params_);
    }
    fclose(cloud_data1);

    delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);


    FILE *plaintext2 = fopen("test/plain2.txt", "rb");
    int buff2;
    fscanf(plaintext2, "%d", &buff2);

    rewind(plaintext2);
 

    LweSample *ciphertext2 = new_gate_bootstrapping_ciphertext_array(32, params_);
    clock_t start9,end9;
    start9= clock();

    for (int i = 0; i < 32; i++){
        //std::cout << ((buff2 >> i) & 1);
        bootsSymEncrypt(&ciphertext2[31-i], (buff2 >> i) & 1, key_);
        //std::cout << "\n";
    }
    end9= clock();
    printf("Encrypt time : %.3f ms\n", (double(end9-start9)/CLOCKS_PER_SEC)*1000);



    fclose(plaintext2);

    FILE *cloud_data2 = fopen("test/cloud2.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(cloud_data2, &ciphertext2[i], params_);
    }
    fclose(cloud_data2);

    delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);


    //delete_gate_bootstrapping_secret_keyset(key_);
    delete_gate_bootstrapping_parameters(params_);



    // Now Compute 


    FILE *cloudKeyFile = fopen("test/cloud.key", "rb");
    auto cloud_key_ = new_tfheGateBootstrappingCloudKeySet_fromFile(cloudKeyFile);
    fclose(cloudKeyFile);

    LweSample *ciphertext_1 = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    FILE *cloud_data_1 = fopen("test/cloud1.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data_1, &ciphertext_1[i], cloud_key_->params);
    fclose(cloud_data_1);


    LweSample *ciphertext_2 = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    FILE *cloud_data_2 = fopen("test/cloud2.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data_2, &ciphertext_2[i], cloud_key_->params);
    fclose(cloud_data_2);

    LweSample *result = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    LweSample *sum = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    LweSample *carry = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);


    clock_t start2,end2;
    start2= clock();
    //onesComplemet(result, ciphertext_1, 32, cloud_key_);
    Compute(result, ciphertext_1, ciphertext_2, 32, cloud_key_);
    //HalfAdder(sum, carry, ciphertext_1, ciphertext_2, 32, cloud_key_);
    end2= clock();
    printf("compute time : %.3f ms\n", (double(end2-start2)/CLOCKS_PER_SEC)*1000);

    LweSample *sum2 = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    LweSample *carry2 = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    bootsSymEncrypt(&carry2[31], 0, key_);
    FullAdder(sum2, carry2, ciphertext_1, ciphertext_2, 32, cloud_key_);

    


    // testing half adder:
    // LweSample *bit_0 = new_gate_bootstrapping_ciphertext_array(2, cloud_key_->params);
    // LweSample *bit_1 = new_gate_bootstrapping_ciphertext_array(2, cloud_key_->params);
printf("Test1");

    printf("Test1");
    // bootsSymEncrypt(&bit_0[0], 0, key_);
    // bootsSymEncrypt(&bit_1[0], 1, key_);





    

    FILE *answer_data = fopen("test/answer.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], cloud_key_->params);
    }
        
    fclose(answer_data);

    FILE *sum_data = fopen("test/sum.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(sum_data, &sum2[i], cloud_key_->params);
    }
        
    fclose(sum_data);

    FILE *carry_data = fopen("test/carry.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(carry_data, &carry2[i], cloud_key_->params);
    }
        
    fclose(carry_data);


    delete_gate_bootstrapping_ciphertext_array(32, result);
    delete_gate_bootstrapping_ciphertext_array(32, sum);
    delete_gate_bootstrapping_ciphertext_array(32, carry);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext_1);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext_2);
    delete_gate_bootstrapping_cloud_keyset(cloud_key_);



    // Decrypt

    FILE *skFile2 = fopen("test/secret.key", "rb");
    auto key2 = new_tfheGateBootstrappingSecretKeySet_fromFile(skFile2);
    fclose(skFile2);

    LweSample *ans = new_gate_bootstrapping_ciphertext_array(32, key2->params);

    FILE *answerData = fopen("test/answer.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(answerData, &ans[i], key2->params);
    fclose(answerData);

    LweSample *sum_ = new_gate_bootstrapping_ciphertext_array(32, key2->params);
    FILE *sumData = fopen("test/sum.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(sumData, &sum_[i], key2->params);
    fclose(sumData);

    LweSample *carry_ = new_gate_bootstrapping_ciphertext_array(32, key2->params);
    FILE *carryData = fopen("test/carry.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(carryData, &carry_[i], key2->params);
    fclose(carryData);

    printf("\nDecryption----\n");

    FILE *dec = fopen("test/decrypt.txt", "wb");
    FILE *sum_dec = fopen("test/sum.txt", "wb");
    FILE *carry_dec = fopen("test/carry.txt", "wb");
    clock_t start3,end3, total3 = 0;

    //Half Adder



    
    for (int i = 0; i < 32; i++){
        start3 = clock();
        int bit = bootsSymDecrypt(&ans[i], key2);
        int sum_bit = bootsSymDecrypt(&sum_[i], key2);
        int carry_bit = bootsSymDecrypt(&carry_[i], key2);
        end3 = clock();
        total3 = total3 + (end3 - start3);
        fprintf(dec, "%d", bit);
        fprintf(sum_dec, "%d", sum_bit);
        fprintf(carry_dec, "%d", carry_bit);
    }
    printf("decrypt time : %.3f ms\n", (double(total3)/CLOCKS_PER_SEC)*1000);
    fclose(dec);
    delete_gate_bootstrapping_ciphertext_array(MAXLEN*8, ans);
    delete_gate_bootstrapping_ciphertext_array(MAXLEN*8, sum_);
    delete_gate_bootstrapping_ciphertext_array(MAXLEN*8, carry_);
    delete_gate_bootstrapping_secret_keyset(key2);

    end1 = clock();

    printf("\nTotal time : %.3f ms", (double(end1-start1)/CLOCKS_PER_SEC)*1000);



return 0;
}