#include <iostream>
#include<bits/stdc++.h>
#include<fstream>
#include <sstream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <time.h>

#define MAXLEN 4



void onesComp(LweSample *result, LweSample *input1, LweSample *input2, const int nbits, const TFheGateBootstrappingCloudKeySet *bk)
{
    for (int i = 0; i < nbits; i++){
        bootsXOR(&result[i], &input1[i], &input2[i], bk);
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

    delete_gate_bootstrapping_ciphertext_array(32, sum1);
    delete_gate_bootstrapping_ciphertext_array(32, carry1);
    delete_gate_bootstrapping_ciphertext_array(32, carry2);
}


void keygen(){

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


}



void encrypt(){

    FILE *skFile = fopen("test/secret.key", "rb");
    auto key_ = new_tfheGateBootstrappingSecretKeySet_fromFile(skFile);
    fclose(skFile);

    FILE *plaintext1 = fopen("test/bootstrap_modules/plain1.txt", "rb");
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
    FILE *cloud_data1 = fopen("test/bootstrap_modules/cloud1.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(cloud_data1, &ciphertext1[i], params_);
    }
    fclose(cloud_data1);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);





    // Encrypting Plaintext2

    FILE *plaintext2 = fopen("test/bootstrap_modules/plain2.txt", "rb");
    int buff2;
    fscanf(plaintext2, "%d", &buff2);
    rewind(plaintext2);
 
    LweSample *ciphertext2 = new_gate_bootstrapping_ciphertext_array(32, params_);
    for (int i = 0; i < 32; i++){
        //std::cout << ((buff2 >> i) & 1);
        bootsSymEncrypt(&ciphertext2[31-i], (buff2 >> i) & 1, key_);
        //std::cout << "\n";
    }
    fclose(plaintext2);
    FILE *cloud_data2 = fopen("test/bootstrap_modules/cloud2.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(cloud_data2, &ciphertext2[i], params_);
    }
    fclose(cloud_data2);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
    //delete_gate_bootstrapping_secret_keyset(key_);






    // Encrypting Plaintext2

    FILE *plaintext3 = fopen("test/bootstrap_modules/plain3.txt", "rb");
    int buff3;
    fscanf(plaintext3, "%d", &buff3);
    rewind(plaintext3);
 
    LweSample *ciphertext3 = new_gate_bootstrapping_ciphertext_array(32, params_);
    for (int i = 0; i < 32; i++){
        //std::cout << ((buff2 >> i) & 1);
        bootsSymEncrypt(&ciphertext3[31-i], (buff3 >> i) & 1, key_);
        //std::cout << "\n";
    }
    fclose(plaintext3);
    FILE *cloud_data3 = fopen("test/bootstrap_modules/cloud3.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(cloud_data3, &ciphertext3[i], params_);
    }
    fclose(cloud_data3);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
    //delete_gate_bootstrapping_secret_keyset(key_);


    FILE *plaintext4 = fopen("test/bootstrap_modules/plain4.txt", "rb");
    int buff4;
    fscanf(plaintext4, "%d", &buff4);
    rewind(plaintext4);
 
    LweSample *ciphertext4 = new_gate_bootstrapping_ciphertext_array(32, params_);
    for (int i = 0; i < 32; i++){
        //std::cout << ((buff2 >> i) & 1);
        bootsSymEncrypt(&ciphertext4[31-i], (buff4 >> i) & 1, key_);
        //std::cout << "\n";
    }
    fclose(plaintext4);
    FILE *cloud_data4 = fopen("test/bootstrap_modules/cloud4.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(cloud_data4, &ciphertext4[i], params_);
    }
    fclose(cloud_data4);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext4);



    // Encrypting allOne
    LweSample *allOne = new_gate_bootstrapping_ciphertext_array(32, params_);
    LweSample *allZero = new_gate_bootstrapping_ciphertext_array(32, params_);
    LweSample *lsbOne = new_gate_bootstrapping_ciphertext_array(32, params_);
    LweSample *lsbZero = new_gate_bootstrapping_ciphertext_array(32, params_);

    for (int i = 0; i < 32; i++){
        bootsSymEncrypt(&allOne[31-i], 1, key_);
    }

    for (int i = 0; i < 32; i++){
        bootsSymEncrypt(&allZero[31-i], 0, key_);
    }

    for (int i = 0; i < 32; i++){
        if(i==0)
            bootsSymEncrypt(&lsbOne[31-i], 1, key_);
        else 
            bootsSymEncrypt(&lsbOne[31-i], 0, key_);
    }

    for (int i = 0; i < 32; i++){
        if(i==0)
            bootsSymEncrypt(&lsbZero[31-i], 0, key_);
        else 
            bootsSymEncrypt(&lsbZero[31-i], 1, key_);
    }

    FILE *all_one = fopen("test/bootstrap_modules/allOne.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(all_one, &allOne[i], params_);
    }
    fclose(all_one);
    delete_gate_bootstrapping_ciphertext_array(32, allOne);

    FILE *all_zero = fopen("test/bootstrap_modules/allZero.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(all_zero, &allZero[i], params_);
    }
    fclose(all_zero);
    delete_gate_bootstrapping_ciphertext_array(32, allZero);


    FILE *lsb_one = fopen("test/bootstrap_modules/lsbOne.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(lsb_one, &lsbOne[i], params_);
    }
    fclose(lsb_one);
    delete_gate_bootstrapping_ciphertext_array(32, lsbOne);

    FILE *lsb_zero = fopen("test/bootstrap_modules/lsbZero.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(lsb_zero, &lsbZero[i], params_);
    }
    fclose(lsb_zero);
    delete_gate_bootstrapping_ciphertext_array(32, lsbZero);


    delete_gate_bootstrapping_parameters(params_);


}




void decrypt_ciphers(LweSample **cipher, int n){
    FILE *skFile = fopen("test/secret.key", "rb");
    auto key_ = new_tfheGateBootstrappingSecretKeySet_fromFile(skFile);
    fclose(skFile);

    printf("........Decrypting ciphers......\n");

    for(int i=0;i<n;i++){
        int num = 0;
        for (int j = 0; j < 32; j++){
            int bit = bootsSymDecrypt(&cipher[i][j], key_);
            num = num*2 + bit;
        }
        printf(" %d", num);
    }
    printf("\n Done \n");

}

int decrypt_cipher(LweSample *cipher){
    FILE *skFile = fopen("test/secret.key", "rb");
    auto key_ = new_tfheGateBootstrappingSecretKeySet_fromFile(skFile);
    fclose(skFile);

    printf("........Decrypting cipher......\n");

    int num = 0;
    for (int j = 0; j < 32; j++){
        int bit = bootsSymDecrypt(&cipher[j], key_);
        num = num*2 + bit;
    }
    printf("Plaintext = %d\n",num);
    return num;
    
}


void difference(LweSample *diff, LweSample *ciphertext_1, LweSample *ciphertext_2, const int nbits ){

    FILE *cloudKeyFile = fopen("test/cloud.key", "rb");
    auto cloud_key_ = new_tfheGateBootstrappingCloudKeySet_fromFile(cloudKeyFile);
    fclose(cloudKeyFile);

    // 2's complement of ciphertext 2
    LweSample *onesComplement = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    LweSample *twosComplement = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);

    LweSample *allOne = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    FILE *all_one = fopen("test/bootstrap_modules/allOne.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(all_one, &allOne[i], cloud_key_->params);
    fclose(all_one);

    LweSample *lsbOne = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    FILE *lsb_one = fopen("test/bootstrap_modules/lsbOne.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(lsb_one, &lsbOne[i], cloud_key_->params);
    fclose(lsb_one);

    LweSample *carry2scomplement = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    FILE *lsb_zero = fopen("test/bootstrap_modules/lsbZero.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(lsb_zero, &carry2scomplement[i], cloud_key_->params);
    fclose(lsb_zero);


    onesComp(onesComplement, allOne, ciphertext_2, 32, cloud_key_);

    // Two's complement of ciphertext2
    FullAdder(twosComplement, carry2scomplement, onesComplement, lsbOne, 32, cloud_key_);


    //LweSample *difference = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    LweSample *borrow = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);

    FILE *f = fopen("test/bootstrap_modules/lsbZero.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(f, &borrow[i], cloud_key_->params);
    fclose(f);

    //diff = cipheretext1 - ciphertext2
    FullAdder(diff, borrow, ciphertext_1, twosComplement, 32, cloud_key_);


    delete_gate_bootstrapping_ciphertext_array(32, onesComplement);
    delete_gate_bootstrapping_ciphertext_array(32, twosComplement);
    delete_gate_bootstrapping_ciphertext_array(32, allOne);
    delete_gate_bootstrapping_ciphertext_array(32, lsbOne);
    delete_gate_bootstrapping_ciphertext_array(32, borrow);
    delete_gate_bootstrapping_ciphertext_array(32, carry2scomplement);
    delete_gate_bootstrapping_cloud_keyset(cloud_key_);

}

void bubble_sort(LweSample **cipher, int n){


    FILE *cloudKeyFile = fopen("test/cloud.key", "rb");
    auto cloud_key_ = new_tfheGateBootstrappingCloudKeySet_fromFile(cloudKeyFile);
    fclose(cloudKeyFile);

    LweSample *allZero = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    FILE *all_zero = fopen("test/bootstrap_modules/allZero.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(all_zero, &allZero[i], cloud_key_->params);
    fclose(all_zero);


    LweSample *diff = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    LweSample *ans1= new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    LweSample *ans2 = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);


    for(int i=1; i<n; i++){
        difference(diff, cipher[i-1], cipher[i], 32);

        for(int j=0;j<32;j++){
            // bigger element
            bootsMUX(&ans1[j],  &diff[0], &cipher[i][j], &cipher[i-1][j], cloud_key_);
            

            // smaller element
            bootsMUX(&ans2[j],  &diff[0], &cipher[i-1][j], &cipher[i][j], cloud_key_);

        }

        for(int j=0; j<32;j++){
            bootsXOR(&cipher[i-1][j], &ans2[j], &allZero[j], cloud_key_);
            bootsXOR(&cipher[i][j], &ans1[j], &allZero[j], cloud_key_);

        }

    }

    delete_gate_bootstrapping_ciphertext_array(32, allZero);
    delete_gate_bootstrapping_ciphertext_array(32, diff);
    delete_gate_bootstrapping_ciphertext_array(32, ans1);
    delete_gate_bootstrapping_ciphertext_array(32, ans2);
    delete_gate_bootstrapping_cloud_keyset(cloud_key_);

}

void compute(){

    FILE *skFile = fopen("test/secret.key", "rb");
    auto key_ = new_tfheGateBootstrappingSecretKeySet_fromFile(skFile);
    fclose(skFile);

    // Full Adder
    FILE *cloudKeyFile = fopen("test/cloud.key", "rb");
    auto cloud_key_ = new_tfheGateBootstrappingCloudKeySet_fromFile(cloudKeyFile);
    fclose(cloudKeyFile);

    LweSample *ciphertext_1 = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    FILE *cloud_data_1 = fopen("test/bootstrap_modules/cloud1.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data_1, &ciphertext_1[i], cloud_key_->params);
    fclose(cloud_data_1);

    LweSample *ciphertext_2 = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    FILE *cloud_data_2 = fopen("test/bootstrap_modules/cloud2.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data_2, &ciphertext_2[i], cloud_key_->params);
    fclose(cloud_data_2);

    LweSample *sum2 = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    LweSample *carry2 = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    bootsSymEncrypt(&carry2[31], 0, key_);

    clock_t start2,end2;
    start2= clock();
    FullAdder(sum2, carry2, ciphertext_1, ciphertext_2, 32, cloud_key_);
    end2= clock();
    printf("Full Adder time : %.3f ms\n", (double(end2-start2)/CLOCKS_PER_SEC)*1000);


    FILE *sum_data = fopen("test/bootstrap_modules/sum.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(sum_data, &sum2[i], cloud_key_->params);
    }   
    fclose(sum_data);

    FILE *carry_data = fopen("test/bootstrap_modules/carry.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(carry_data, &carry2[i], cloud_key_->params);
    }
     fclose(carry_data);


    // Subtractor

    // 2's complement of ciphertext 2
    LweSample *onesComplement = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);

    LweSample *twosComplement = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    LweSample *carry2scomplement = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);

    LweSample *allOne = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    FILE *all_one = fopen("test/bootstrap_modules/allOne.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(all_one, &allOne[i], cloud_key_->params);
    fclose(all_one);

    LweSample *lsbOne = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    FILE *lsb_one = fopen("test/bootstrap_modules/lsbOne.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(lsb_one, &lsbOne[i], cloud_key_->params);
    fclose(lsb_one);

    bootsSymEncrypt(&carry2scomplement[31], 0, key_);



    onesComp(onesComplement, allOne, ciphertext_2, 32, cloud_key_);
    // for (int i = 0; i < 32; i++){
    //     int bit = bootsSymDecrypt(&onesComplement[i], key_);
    //     printf("%d", bit);
    // }



    FullAdder(twosComplement, carry2scomplement, onesComplement, lsbOne, 32, cloud_key_);
    // for (int i = 0; i < 32; i++){
    //     int bit = bootsSymDecrypt(&twosComplement[i], key_);
    //     printf("%d", bit);
    // }

    LweSample *difference = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    bootsSymEncrypt(&carry2scomplement[31], 0, key_);
    FullAdder(difference, carry2scomplement, ciphertext_1, twosComplement, 32, cloud_key_);

    FILE *diff_data = fopen("test/bootstrap_modules/diff.data", "wb");
    for (int i = 0; i < 32; i++){
        export_gate_bootstrapping_ciphertext_toFile(diff_data, &difference[i], cloud_key_->params);
    }   
    fclose(diff_data);


    // Shift and add multiply
    // ciphertext2 is assumed to be multiplier (Q)
    // ciphertext1 is assume to be multiplicand (B)

    LweSample *A_reg = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    LweSample *C_reg = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);

    for (int i = 0; i < 32; i++){
            bootsSymEncrypt(&A_reg[31-i], 0, key_);
    }




// bubble sorting

    LweSample **cipher = new LweSample*[4];

    for(int i=0;i<4;i++){
        cipher[i] = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    }

    FILE *cloud1 = fopen("test/bootstrap_modules/cloud1.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud1, &cipher[0][i], cloud_key_->params);
    fclose(cloud1);

    FILE *cloud2 = fopen("test/bootstrap_modules/cloud2.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud2, &cipher[1][i], cloud_key_->params);
    fclose(cloud2);

    FILE *cloud3 = fopen("test/bootstrap_modules/cloud3.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud3, &cipher[2][i], cloud_key_->params);
    fclose(cloud3);

    FILE *cloud4 = fopen("test/bootstrap_modules/cloud4.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud4, &cipher[3][i], cloud_key_->params);
    fclose(cloud4);

    decrypt_ciphers(cipher, 4);

    //bubble_sort(cipher, 4);

    printf("\nAfter Bubble sorting\n");

    decrypt_ciphers(cipher, 4);


    delete_gate_bootstrapping_ciphertext_array(32, sum2);
    delete_gate_bootstrapping_ciphertext_array(32, carry2);
    delete_gate_bootstrapping_ciphertext_array(32, onesComplement);
    delete_gate_bootstrapping_ciphertext_array(32, allOne);
    delete_gate_bootstrapping_ciphertext_array(32, twosComplement);
    delete_gate_bootstrapping_ciphertext_array(32, lsbOne);
    delete_gate_bootstrapping_ciphertext_array(32, difference);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext_1);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext_2);
    delete_gate_bootstrapping_cloud_keyset(cloud_key_);

}



void decrypt(){
    FILE *skFile2 = fopen("test/secret.key", "rb");
    auto key2 = new_tfheGateBootstrappingSecretKeySet_fromFile(skFile2);
    fclose(skFile2);

    LweSample *sum_adder = new_gate_bootstrapping_ciphertext_array(32, key2->params);
    FILE *sumData = fopen("test/bootstrap_modules/sum.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(sumData, &sum_adder[i], key2->params);
    fclose(sumData);

    LweSample *carry_adder = new_gate_bootstrapping_ciphertext_array(32, key2->params);
    FILE *carryData = fopen("test/bootstrap_modules/carry.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(carryData, &carry_adder[i], key2->params);
    fclose(carryData);

    LweSample *diff_adder = new_gate_bootstrapping_ciphertext_array(32, key2->params);
    FILE *diffData = fopen("test/bootstrap_modules/diff.data", "rb");
    for (int i = 0; i < 32; i++)
        import_gate_bootstrapping_ciphertext_fromFile(diffData, &diff_adder[i], key2->params);
    fclose(diffData);

    printf("\nDecryption----\n");

    FILE *sum_dec = fopen("test/bootstrap_modules/sum.txt", "wb");
    FILE *carry_dec = fopen("test/bootstrap_modules/carry.txt", "wb");
    FILE *diff_dec = fopen("test/bootstrap_modules/diff.txt", "wb");
    clock_t start3,end3, total3 = 0;

    
    for (int i = 0; i < 32; i++){
        start3 = clock();
        int sum_bit = bootsSymDecrypt(&sum_adder[i], key2);
        int carry_bit = bootsSymDecrypt(&carry_adder[i], key2);
        int diff_bit = bootsSymDecrypt(&diff_adder[i], key2);
        end3 = clock();
        total3 = total3 + (end3 - start3);
        fprintf(sum_dec, "%d", sum_bit);
        fprintf(carry_dec, "%d", carry_bit);
        fprintf(diff_dec, "%d", diff_bit);
    }
    printf("decrypt time : %.3f ms\n", (double(total3)/CLOCKS_PER_SEC)*1000);
    delete_gate_bootstrapping_ciphertext_array(MAXLEN*8, sum_adder);
    delete_gate_bootstrapping_ciphertext_array(MAXLEN*8, carry_adder);
    delete_gate_bootstrapping_ciphertext_array(MAXLEN*8, diff_adder);
    delete_gate_bootstrapping_secret_keyset(key2);
}




void encrypt_dataset(LweSample **ciphers, std::vector<int>&row){

    FILE *skFile = fopen("test/secret.key", "rb");
    auto key_ = new_tfheGateBootstrappingSecretKeySet_fromFile(skFile);
    fclose(skFile);

    FILE *paramFile = fopen("test/secret.params", "rb");
    auto params_ = new_tfheGateBootstrappingParameterSet_fromFile(paramFile);
    fclose(paramFile); 

    for(int i=0; i<row.size();i++){

        for(int j = 0; j < 32; j++){
            bootsSymEncrypt(&ciphers[i][31-j], (row[i] >> j) & 1, key_);
        }
    }

    delete_gate_bootstrapping_secret_keyset(key_);
    delete_gate_bootstrapping_parameters(params_);
}


void distance(LweSample *input1, LweSample *input2, const int n){

    FILE *cloudKeyFile = fopen("test/cloud.key", "rb");
    auto cloud_key_ = new_tfheGateBootstrappingCloudKeySet_fromFile(cloudKeyFile);
    fclose(cloudKeyFile);

    LweSample *difference1 = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    LweSample *difference2 = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    LweSample *difference3 = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);

    difference(difference1, input1, input2, n);
    difference(difference2, input2, input1, n);

    //Homomorphic bootstrapped Mux(a,b,c) = a?b:c = a*b + not(a)*c
    for(int i=0; i<n; i++){
        bootsMUX(&difference3[i], &difference1[0], &difference2[i], &difference1[i], cloud_key_);
    }

    printf("\n------------Calculating Distance ------\n");
    int dist =  decrypt_cipher(difference3);
    printf("Distance = %d\n", dist);

    delete_gate_bootstrapping_ciphertext_array(MAXLEN*8, difference1);
    delete_gate_bootstrapping_ciphertext_array(MAXLEN*8, difference2);
    delete_gate_bootstrapping_ciphertext_array(MAXLEN*8, difference3);
    delete_gate_bootstrapping_cloud_keyset(cloud_key_);
    

}


void inputDataSet()
{
    FILE *cloudKeyFile = fopen("test/cloud.key", "rb");
    auto cloud_key_ = new_tfheGateBootstrappingCloudKeySet_fromFile(cloudKeyFile);
    fclose(cloudKeyFile);

    int row_size = 5, col_size = 14;
    std::vector<std::vector<int>> row(row_size);
    std::string line, word, temp;

    std::ifstream read("test/bootstrap_modules/data.csv"); 
    read>>line;


    // LweSample **cipher_data = new LweSample*[col_size];
    LweSample ***cipher_dataset = new LweSample**[col_size];

    // for(int i=0;i<col_size;i++){
    //     cipher_data[i] = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
    // }


    for(int i=0;i<row_size;i++){
        cipher_dataset[i] = new LweSample*[col_size];
        for(int j=0; j<col_size; j++){
            cipher_dataset[i][j] = new_gate_bootstrapping_ciphertext_array(32, cloud_key_->params);
        }
        
    }

    int row_count = 0;
    while (read >> line)
    {
        row[row_count] = std::vector<int>(col_size);
        row[row_count].clear();
        //std::cout << line << std::endl;

        std::stringstream s(line);
  
        while (std::getline(s, word, ',')) {
        //std::cout << word<<" ";

        std::stringstream ss(word);
        int x =0;
        ss >> x;
        row[row_count].push_back(x);
        }
        //std::cout<<"\n";

        // for(int i=0; i<row[row_count].size();i++){
        //     printf("%d ",row[row_count][i]);
        // }
        // printf("\n");

        encrypt_dataset(cipher_dataset[row_count], row[row_count]);
        //distance(cipher_dataset[row_count][1], cipher_dataset[row_count][2], 32);
        decrypt_ciphers(cipher_dataset[row_count], col_size);
        bubble_sort(cipher_dataset[row_count], col_size);
        decrypt_ciphers(cipher_dataset[row_count], col_size);


    row_count++;
    if(row_count == row_size)
        break;
    }

    delete_gate_bootstrapping_cloud_keyset(cloud_key_);
    // for(int i=0;i<col_size;i++){
    //     delete_gate_bootstrapping_ciphertext_array(MAXLEN*8, cipher_data[i]);
    // }

    for(int i=0; i<row_size; i++){
        for(int j=0; j<col_size; j++){
            delete_gate_bootstrapping_ciphertext_array(MAXLEN*8, cipher_dataset[i][j]);
        }
    }
        
}

int main()
{
 
    clock_t start1, end1;
    start1 = clock();

    keygen();


    // Now encrypt the message....

    // Encryptiong Plaintext1



    //encrypt();




    // Now Compute 

    //compute();


    // Decrypt

    //decrypt();

    end1 = clock();

    printf("\nTotal time : %.3f ms \n", (double(end1-start1)/CLOCKS_PER_SEC)*1000);


    inputDataSet();



return 0;
}