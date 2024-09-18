#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <tfhe/lwe-functions.h>
#include <tfhe/numeric_functions.h>
#include <tfhe/tlwe_functions.h>
#include <random>
#include <time.h>


void profile(int coeff, int iter)
{
    TLweParams *params2 = new TLweParams(1024 * coeff, 2, 0.01, 0.2);

    struct timespec start_time = {0, 0};
    struct timespec end_time = {0, 0};

    clock_gettime(CLOCK_MONOTONIC, &start_time);
    for (int i = 0; i < iter; i++){
        auto key = new TLweKey(params2);
        delete key;
    }
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    std::cout << "Time taken: " << ((double)end_time.tv_nsec + 1.0e+9 * end_time.tv_sec) - ((double)start_time.tv_nsec + 1.0e+9 * start_time.tv_sec) << std::endl;
}


int main(int argc, char *argv[])
{
    int coeff = atoi(argv[1]);
    int iter = atoi(argv[2]);

    profile(coeff, iter);

    return 0;
}