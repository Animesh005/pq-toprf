#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <tfhe/lwe-functions.h>
#include <tfhe/numeric_functions.h>
#include <tfhe/tlwe_functions.h>
#include <random>
#include <chrono>

#define ITER 100000

using namespace std::chrono;

int main()
{
    std::cout << "Starting LWE...." << std::endl;
    LweParams *p1 = new_LweParams(2048, 0.01, 0.2);
    LweKey *k1 = new_LweKey(p1);
    lweKeyGen(k1);
    LweSample *r1 = new_LweSample(p1);

    long long te1 = 0, td1 = 0;
    for (int i = 0; i < ITER; i++){
        if (i % 1000 == 0)
            std::cout << "Iter " << i << std::endl;
        
        int bit = rand();
        if (bit > RAND_MAX / 2){
            bit = 1;
        }else{
            bit = 0;
        }

        auto start1 = high_resolution_clock::now();
        lweSymEncrypt(r1, modSwitchToTorus32(bit, 2), 0.001, k1);
        auto stop1 = high_resolution_clock::now();

        auto duration1 = duration_cast<microseconds>(stop1 - start1);
        te1 += duration1.count();

        auto start2 = high_resolution_clock::now();
        lweSymDecrypt(r1, k1, 2);
        auto stop2 = high_resolution_clock::now();

        auto duration2 = duration_cast<microseconds>(stop2 - start2);
        td1 += duration2.count();
    }

    std::cout << "Starting TLWE...." << std::endl;
    TLweParams *p2 = new_TLweParams(1024, 2, 0.01, 0.2);
    TLweKey *k2 = new_TLweKey(p2);
    tLweKeyGen(k2);
    TLweSample *r2 = new_TLweSample(p2);

    long long te2 = 0, td2 = 0;
    for (int i = 0; i < ITER; i++){
        if (i % 1000 == 0)
            std::cout << "Iter " << i << std::endl;
        
        int bit = rand();
        if (bit > RAND_MAX / 2){
            bit = 1;
        }else{
            bit = 0;
        }

        auto start1 = high_resolution_clock::now();
        tLweSymEncryptT(r2, modSwitchToTorus32(bit, 2), 0.001, k2);
        auto stop1 = high_resolution_clock::now();

        auto duration1 = duration_cast<microseconds>(stop1 - start1);
        te2 += duration1.count();

        auto start2 = high_resolution_clock::now();
        tLweSymDecryptT(r2, k2, 2);
        auto stop2 = high_resolution_clock::now();

        auto duration2 = duration_cast<microseconds>(stop2 - start2);
        td2 += duration2.count();
    }

    std::cout << "====================" << std::endl;
    std::cout << "Average LWE Encryption time: " << te1 / ITER << " ms" << std::endl;
    std::cout << "Average LWE Decryption time: " << td1 / ITER << " ms" << std::endl;
    std::cout << "Average TLWE Encryption time: " << te2 / ITER << " ms" <<  std::endl;
    std::cout << "Average TLWE Decryption time: " << td2 / ITER << " ms" <<  std::endl;
}