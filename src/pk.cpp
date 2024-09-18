#include <iostream>
#include <random>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <tfhe/tfhe_garbage_collector.h>
#include "threshold_decryption_functions.hpp"
#define MSIZE 2

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

TFheGateBootstrappingParameterSet *initialize_gate_bootstrapping_params() {
    static const int32_t N = 1024;
    static const int32_t k = 1;
    static const int32_t n = 1024;
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


/* Pubkey is just a set of encryptions of 0.
 * b_i = a_i * s + e_i
 * To encrypt:
 * Randomly choose a subset, take sum, add message to sum(b_i).
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
            // bootsSymEncrypt(samples[i], 0, sk);
            lweSymEncrypt(samples[i], modSwitchToTorus32(0, MSIZE), alpha, sk->lwe_key);
            // for (int j = 0; j < n; j++){
            //     samples[i]->a[j] /= n_samples;
            // }
            // samples[i]->b /= n_samples;
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
            // std::cout << "CHOICE: " << choice << std::endl;
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
        // bootsSymEncrypt
        // result->b = gaussian32(message, alpha);
        result->b = mu + gaussian32(0, alpha);
        result->b += B;
        for (int32_t i = 0; i < n; ++i)
        {
            result->a[i] = A[i];
        }
        result->current_variance = alpha*alpha; // Non-functional
    }



};


int main()
{
    // const int minimum_lambda = 110;
    auto params = initialize_gate_bootstrapping_params();

    uint32_t seed[] = { 100, 20032, 21341 };
    tfhe_random_generator_setSeed(seed, 3);
    // Torus32 myvar = modSwitchToTorus32(1,8);
    // std::cout << myvar << "\n";
    auto key = new_random_gate_bootstrapping_secret_keyset(params);

    auto pk = PubKey(key, 1);
    int r;
    TLweParams *tlwe_params = new_TLweParams(1024, 1, 0.01, 0.2);
    TLweKey *tlwe_key = new_TLweKey(tlwe_params);
    tLweKeyGen(tlwe_key);

    

    TLweKeyFromLweKey(key->lwe_key, tlwe_key);

    shareSecret(3, 5, tlwe_key, tlwe_params);

    
    int result_msg;
    std::vector<int> subset{1,2,4};
    
    for (int i = 0; i < 1000; i++){
        double bound = 0.0125;
        LweSample *ciphertext = new_LweSample(key->lwe_key->params);

        pk.Encrypt(ciphertext, i % 2);
        r = bootsSymDecrypt(ciphertext, key);
        TLweSample *resultOfEvalT;
        TorusPolynomial *result_plaintext;
        while(bound > 1e-3){
            result_msg = 0;
            //Assuming k = 1, n = N = 1024, and converting lwe ciphertext of each of the result bit into corresponding ring-lwe ciphertext one by one and decrypting
            //TODO: Pack all 32 lwe ciphertexts into one tlwe ciphertext and call threshold_decryption once
            //NEXT TODO: Do the same but with k > 1
            // for (int i = 0; i < 32; i++){
            resultOfEvalT = new_TLweSample(tlwe_params);
            TLweFromLwe(resultOfEvalT, ciphertext, tlwe_params);
            result_plaintext = new_TorusPolynomial(tlwe_params->N);
            thresholdDecrypt(result_plaintext, resultOfEvalT, tlwe_params, subset, 3, 5, bound);
            result_msg = result_plaintext->coefsT[0] > 0 ? 1 : 0;
            // }
            if(i%2 != result_msg)
                std::cout << i << "-> expected: " << i % 2 << ", direct decrypt: " << r << ", bound: " << bound << ", thresdold decrypt: " << result_msg << "\n";
            bound /= 2;
        }
        delete_LweSample(ciphertext);
    }
        delete_gate_bootstrapping_secret_keyset(key);
        delete_gate_bootstrapping_parameters(params);

    return 0;
}
