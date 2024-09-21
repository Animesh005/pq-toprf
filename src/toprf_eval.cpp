#include <iostream>
#include <random>
#include <array>
#include <vector>
#include <stdio.h>
#include <ctime>
#include <cstdint>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <cstdlib>
#include <cmath>
#include <sys/time.h>
#include <bits/stdc++.h>

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <tfhe/lwe-functions.h>
#include <tfhe/numeric_functions.h>
#include <tfhe/tlwe_functions.h>
#include <tfhe/tfhe_garbage_collector.h>
#include "threshold_decryption_functions.hpp"
#define MSIZE 2

using namespace std;

// Initialize PRF parameters
int in_size = 128;
int out_size = 128;

int in_arr_size = 36663;
int out_arr_size = 36920;

// Create random pair of bits (r_0^i, r_1^i)
vector<vector<int>> r_pair(2, std::vector<int>(in_arr_size));

// Create the encryptio of random pair of bits (r_0^i, r_1^i)
vector<vector<LweSample*>> enc_pair(2, std::vector<LweSample*>(in_arr_size));

// Create an empty LUT
std::vector<std::vector<std::vector<LweSample*>>> LUT(in_arr_size, std::vector<std::vector<LweSample*>>(2, std::vector<LweSample*>(2)));

// Initialize LWE parameters
TFheGateBootstrappingParameterSet *initialize_gate_bootstrapping_params() {
    static const int32_t N = 1024;
    static const int32_t k = 1;
    static const int32_t n = 500;
    static const int32_t bk_l = 3;
    static const int32_t bk_Bgbit = 7;
    static const int32_t ks_basebit = 2;
    static const int32_t ks_length = 8;
    static const double ks_stdev = pow(2.,-15); //standard deviation
    static const double bk_stdev = pow(2.,-25);; //standard deviation
    static const double max_stdev = 0.012467; //max standard deviation for a 1/4 msg space

    LweParams *params_in = new_LweParams(n, ks_stdev, max_stdev);
    TLweParams *params_accum = new_TLweParams(N, k, bk_stdev, max_stdev);
    TGswParams *params_bk = new_TGswParams(bk_l, bk_Bgbit, params_accum);

    TfheGarbageCollector::register_param(params_in);
    TfheGarbageCollector::register_param(params_accum);
    TfheGarbageCollector::register_param(params_bk);

    return new TFheGateBootstrappingParameterSet(ks_length, ks_basebit, params_in, params_bk);
}

// A structure to represent an 80-bit seed
// struct Seed80 {
//     uint32_t part1; // Lower 32 bits
//     uint32_t part2; // Middle 32 bits
//     uint16_t part3; // Upper 16 bits
// };

// // Function to combine the 80-bit seed into a seed sequence (The Mersenne Twister)
// std::seed_seq generateSeedSeq(const Seed80& seed) {
//     // Combine parts into a vector of 32-bit integers
//     std::array<uint32_t, 3> seedArray = { seed.part1, seed.part2, seed.part3 };
//     return std::seed_seq(seedArray.begin(), seedArray.end());
// }

void TLweFromLwe(TLweSample *ring_cipher, LweSample *cipher, TLweParams *tlwe_params){
    int N = tlwe_params->N;
    ring_cipher->a[0].coefsT[0] = cipher->a[0];
    ring_cipher->b->coefsT[0] = cipher->b;
    for(int i = 1; i < N; i++){
        ring_cipher->a[0].coefsT[i] = -cipher->a[N-i];
    }
}

void TLweKeyFromLweKey(const LweKey *lwe_key, TLweKey *tlwe_key){
    int N = tlwe_key->params->N;
    tlwe_key->key[0].coefs[0] = lwe_key->key[0];
    for(int i = 0; i < N; i++){
        tlwe_key->key[0].coefs[i] = lwe_key->key[i];
    }
}

/* Pubkey is just a set of encryptions of 0.
 * b_i = a_i * s + e_i
 * To encrypt: Randomly choose a subset, take sum, add message to sum(b_i).
 */
class PubKey {
    LweSample **samples;
    int n;
    int n_samples;
    double alpha;

private:
    std::default_random_engine generator;
    std::uniform_int_distribution<int> *distribution;

public:
    PubKey(TFheGateBootstrappingSecretKeySet *sk, int n_samples)
    {
        this->n = sk->lwe_key->params->n;
        this->n_samples = n_samples;
        samples = new LweSample*[n_samples];
        alpha = sk->params->in_out_params->alpha_min;
        distribution = new std::uniform_int_distribution<int>(0, 1);
        for (int i = 0; i < n_samples; i++){
            samples[i] = new_LweSample(sk->lwe_key->params);
            lweSymEncrypt(samples[i], modSwitchToTorus32(0, MSIZE), alpha, sk->lwe_key);
        }
        
    }

    void Encrypt(LweSample *result, int32_t message)
    {
        // Random sum
        Torus32 *A = new Torus32[n];
        Torus32 B = 0;
        
        for (int i = 0; i < n; i++){
            A[i] = 0;
        }

        for (int i = 0; i < n_samples; i++){
            int choice = (*distribution)(generator);
            if (choice){
                for (int j = 0; j < n; j++){
                    A[j] += samples[i]->a[j];
                }
                B += samples[i]->b;
            }
        }

        // Add message
        Torus32 _1s8 = modSwitchToTorus32(1, 8);
        Torus32 mu = message ? _1s8 : -_1s8;
        
        result->b = mu + gaussian32(0, alpha);
        result->b += B;
        for (int32_t i = 0; i < n; ++i)
        {
            result->a[i] = A[i];
        }
        result->current_variance = alpha*alpha;
    }

};

int threshold_decrypt_lisss(LweSample *ciphertext, const LweKey *lwe_key, int t, int p)
{
    double bound = 0.0125;
    // std::vector<int> parties{1,2,3};
    std::vector<int> parties(t);
    std::iota(parties.begin(), parties.end(), 1);

    TLweParams *tlwe_params = new_TLweParams(1024, 1, 0.01, 0.2);
    TLweKey *tlwe_key = new_TLweKey(tlwe_params);
    tLweKeyGen(tlwe_key);

    // secret share sk
    TLweKeyFromLweKey(lwe_key, tlwe_key);
    shareSecret2(t, p, tlwe_key, tlwe_params);

    auto resultOfEvalT = new_TLweSample(tlwe_params);
    TLweFromLwe(resultOfEvalT, ciphertext, tlwe_params);
    auto result_plaintext = new_TorusPolynomial(tlwe_params->N);

    // threshold decrypt ciphertext
    thresholdDecrypt(result_plaintext, resultOfEvalT, tlwe_params, parties, t, p, bound);
    auto result_msg = result_plaintext->coefsT[0] > 0 ? 1 : 0;
    
    return result_msg;
}

int threshold_decrypt_additive(LweSample *ciphertext, const LweKey *lwe_key, int p)
{
    // This uses additive secret sharing 
    int n = lwe_key->params->n;
    std::vector<std::vector<int32_t>> shares(p, std::vector<int32_t>(n));

    for (size_t i = 0; i < n; ++i) {
        int32_t sum = 0;
        
        // Generate t-1 random shares
        for (size_t j = 0; j < p - 1; ++j) {
            shares[j][i] = std::rand();
            sum += shares[j][i];
    }
    
        // Calculate the t-th share to satisfy the secret sharing requirement
        shares[p-1][i] = lwe_key->key[i] - sum;

    }

    // const int32_t n = key->params->n;
    Torus32 axs = 0;
    const Torus32 *__restrict a = ciphertext->a;
    const int32_t * __restrict k = lwe_key->key;

    for (size_t j=0; j < p; j++)
    {
        for (int32_t i = 0; i < n; ++i) 
	        axs += a[i]*shares[j][i]; 
    }

    Torus32 mu = ciphertext->b - axs;
    return (mu > 0 ? 1 : 0);

}

// Read PRF netlist
std::vector<std::vector<int>> readNetlist(const std::string& filename) {
    std::ifstream file(filename);
    std::vector<std::vector<int>> result;

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::vector<int> temp;
        int val;
        while (iss >> val) {
            temp.push_back(val);
        }

        result.push_back(temp);
    }
    std::cout << result.size() << "\n";

    return result;
}

// Function to perform PRF evaluation
void PRFEval(vector<LweSample*> &enc_prf_output, const vector<std::vector<int>>& netlist, const vector<LweSample*>& enc_prf_msg, 
                                const vector<LweSample*>& enc_prf_key, vector<LweSample*>& prf_output_arr, const LweParams *params, 
                                const LweKey *key, const TFheGateBootstrappingCloudKeySet *bk, int t, int p, int flag) {


    // Fill first 256 bits of output array with 128 bit prf encrypted msg and 128 bit prf encrypted key
    for (int i = 0; i < in_size; ++i) {
        lweCopy(prf_output_arr[i], enc_prf_msg[i], params);
        lweCopy(prf_output_arr[i + in_size], enc_prf_key[i], params);
    }

    for (int i = 0; i < netlist.size(); ++i) {
    
        if (netlist[i].front() == 2) { // XOR/AND operation
            int in1 = netlist[i][2];
            int in2 = netlist[i][3];
            int out = netlist[i][4];
            
            const LweParams *in_out_params = bk->params->in_out_params;
            LweSample *temp_result1 = new_LweSample(in_out_params);
            LweSample *temp_result2 = new_LweSample(in_out_params);

            //compute: (0,1/4) + 2*(ca + cb)
            static const Torus32 XorConst = modSwitchToTorus32(1, 4);
            lweNoiselessTrivial(temp_result1, XorConst, in_out_params);
            lweNoiselessTrivial(temp_result2, XorConst, in_out_params);

            lweAddMulTo(temp_result1, 2, prf_output_arr[in1], in_out_params);
            lweAddMulTo(temp_result1, 2, enc_pair[0][i], in_out_params);

            lweAddMulTo(temp_result2, 2, prf_output_arr[in2], in_out_params);
            lweAddMulTo(temp_result2, 2, enc_pair[1][i], in_out_params);

            if (flag == 1){
                auto result_msg1 = threshold_decrypt_lisss(temp_result1, key, t, p);
                auto result_msg2 = threshold_decrypt_lisss(temp_result2, key, t, p);

                lweCopy(prf_output_arr[out], LUT[i][result_msg1][result_msg2], params);
            }
            else{
                auto result_msg1 = threshold_decrypt_additive(temp_result1, key, p);
                auto result_msg2 = threshold_decrypt_additive(temp_result2, key, p);

                lweCopy(prf_output_arr[out], LUT[i][result_msg1][result_msg2], params);
            }

            delete_LweSample(temp_result1);
            delete_LweSample(temp_result2);

        }
        else{ // NOT operation
            int in1 = netlist[i][2];
            int out = netlist[i][3];

            bootsNOT(prf_output_arr[out], prf_output_arr[in1], bk);
        }
    }

    for(int i = 0; i < out_size; i++){
        lweCopy(enc_prf_output[out_size-1-i], prf_output_arr[prf_output_arr.size()-1-i], params);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Few parameters! please provide t, p, flag" << std::endl;
        return 1;
    }

    int t = std::atoi(argv[1]);
    int p = std::atoi(argv[2]);
    int flag = std::atoi(argv[3]);

    // Initialize the 80-bit seed
    // Seed80 seed_prg = {0x12345678, 0x9ABCDEF0, 0x1357};

    // Generate a seed sequence from the 80-bit seed
    // std::seed_seq seedSeq = generateSeedSeq(seed_prg);

    // Create the Mersenne Twister PRNG with the given seed sequence
    // std::mt19937 prng(seedSeq);

    // Generate and print 32 x n bits (here n = 500 for demonstration)
    // for (int i = 0; i < 500; ++i) {
    //     uint32_t random_number = prng();
    //     std::cout << random_number << std::endl;
    // }

    auto tfheParams = initialize_gate_bootstrapping_params();
    auto params = tfheParams->in_out_params;

    // Key generation 
    auto sk = new_random_gate_bootstrapping_secret_keyset(tfheParams);
    auto bk = &sk->cloud;

    auto pk = PubKey(sk, 1);

    // Populate the random pair of bits (r_0^i, r_1^i)
    for (int i= 0; i < in_arr_size; i++)
    {
        r_pair[0][i]= rand() % 2; // Message
        r_pair[1][i]= rand() % 2; // Key
    }

    // Fill the encrypted bit pair array
    for (int i = 0; i < in_arr_size; ++i) {
        enc_pair[0][i] = new_LweSample(params);
        pk.Encrypt(enc_pair[0][i], r_pair[0][i]);

        enc_pair[1][i] = new_LweSample(params);
        pk.Encrypt(enc_pair[1][i], r_pair[1][i]);
    }

    // Read PRF netlist
    cout << "\n\nLoading Circuit . . ." << endl;
    vector<vector<int>> prf_netlist = readNetlist("test/aes_128.txt");

    for (int i = 0; i < prf_netlist.size(); ++i) {
        for (int j = 0; j < 2; ++j) {
            for (int k = 0; k < 2; ++k) {
                LUT[i][j][k] = new_LweSample(params);  // Dynamically allocate memory
            }
        }
    }

    // Fill the LUTs
    for (int i = 0; i < prf_netlist.size(); ++i) {
    
        if (prf_netlist[i].back() == 0) { // XOR operation
            int temp_00 = (0 ^ r_pair[0][i]) ^ (0 ^ r_pair[1][i]);
            pk.Encrypt(LUT[i][0][0], temp_00);

            int temp_01 = (0 ^ r_pair[0][i]) ^ (1 ^ r_pair[1][i]);
            pk.Encrypt(LUT[i][0][1], temp_01);

            int temp_10 = (1 ^ r_pair[0][i]) ^ (0 ^ r_pair[1][i]);
            pk.Encrypt(LUT[i][1][0], temp_10);

            int temp_11 = (1 ^ r_pair[0][i]) ^ (1 ^ r_pair[1][i]);
            pk.Encrypt(LUT[i][1][1], temp_11);

        }

        else if (prf_netlist[i].back() == 1) { // AND operation
            int temp_00 = (0 ^ r_pair[0][i]) & (0 ^ r_pair[1][i]);
            pk.Encrypt(LUT[i][0][0], temp_00);

            int temp_01 = (0 ^ r_pair[0][i]) & (1 ^ r_pair[1][i]);
            pk.Encrypt(LUT[i][0][1], temp_01);

            int temp_10 = (1 ^ r_pair[0][i]) & (0 ^ r_pair[1][i]);
            pk.Encrypt(LUT[i][1][0], temp_10);

            int temp_11 = (1 ^ r_pair[0][i]) & (1 ^ r_pair[1][i]);
            pk.Encrypt(LUT[i][1][1], temp_11);

        }
        else{ // NOT operation
            continue;
        }
    }
    
    vector<vector<int>> inp(2, std::vector<int>(in_size));
    vector<int> outp(out_size);

    // Load inputs of PRF (random values for demonstration)
    for (int i= 0; i < in_size; i++)
    {
        inp[0][i]= rand() % 2; // Message
        inp[1][i]= rand() % 2; // Key
    }
    
    cout << "\n\nMessage: " << endl;
    for (int i=0; i < in_size; i++)
        cout << inp[0][i] << " ";

    cout << "\n\nKey: " << endl;
    for (int i=0; i < in_size; i++)
        cout << inp[1][i] << " ";

    // Initialize prf msg and prf key
    std::vector<LweSample*> prf_msg(in_size);
    std::vector<LweSample*> prf_key(in_size);

    // Encrypt prf msg and prf key
    std::vector<LweSample*> enc_prf_msg(in_size);
    std::vector<LweSample*> enc_prf_key(in_size);

    for (int i = 0; i < in_size; ++i) {
        enc_prf_msg[i] = new_LweSample(params);
        pk.Encrypt(enc_prf_msg[i], inp[0][i]);

        enc_prf_key[i] = new_LweSample(params);
        pk.Encrypt(enc_prf_key[i], inp[1][i]);
    }

    // Initialize an output array with enc of 0
    std::vector<LweSample*> prf_output_arr(out_arr_size);

    for (int i = 0; i < prf_output_arr.size(); i++){
        prf_output_arr[i] = new_LweSample(params);
        // pk.Encrypt(prf_output_arr[i], 0);
    }

    std::vector<LweSample*> enc_prf_output;
    enc_prf_output.resize(out_size);
    for (int i = 0; i < enc_prf_output.size(); i++)
        enc_prf_output[i] = new_LweSample(params);

    // Evaluate prf circuit
    cout << "\n\nEvaluating Circuit . . ." << endl;
    clock_t begin_eval = clock();
    
    PRFEval(enc_prf_output, prf_netlist, enc_prf_msg, enc_prf_key, prf_output_arr, params, sk->lwe_key, bk, t, p, flag);
    
    clock_t end_eval = clock();
    double time_eval = ((double) end_eval - begin_eval)/CLOCKS_PER_SEC;
    cout << "Finished Evaluation: " << time_eval << " seconds"<< endl;

    // Decrypt the prf output
    std::cout << "\n\nfinal decryption\n";
    std::vector<int> prf_clear_output(out_size);

    for (int i = 0; i < in_size; ++i) {
        // std::cout << bootsSymDecrypt(enc_prf_output[i], sk) << " ";
        prf_clear_output[i] = bootsSymDecrypt(enc_prf_output[i], sk);
    }

    // Print prf clear output
    for (int bit : prf_clear_output) {
        std::cout << bit << " ";
    }
    std::cout << "\n";

    return 0;
}
