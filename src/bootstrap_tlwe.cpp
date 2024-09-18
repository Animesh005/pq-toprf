#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <tfhe/lwe-functions.h>
#include <tfhe/numeric_functions.h>
#include <tfhe/tlwe_functions.h>
#include <random>
#include <time.h>
#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/io.hpp>
#include <boost/numeric/ublas/matrix_proxy.hpp>
#include <boost/numeric/ublas/blas.hpp>
#include <bits/stdc++.h>
#include "threshold_decryption_functions.hpp"
#include "threshold_decryption_vars.hpp"

#define MSIZE 2

namespace ublas = boost::numeric::ublas;

int ncrT(int n, int r){
    if (ncr_cacheT.find({n, r}) == ncr_cacheT.end()){
        if (r > n || n < 0 || r < 0)
            return 0;
        else{
            if (r == 0 || r == n){
                ncr_cacheT[{n, r}] = 1;
            }else if (r == 1 || r == n - 1){
                ncr_cacheT[{n, r}] = n;
            }else{
                ncr_cacheT[{n, r}] = ncrT(n - 1, r) + ncrT(n - 1, r - 1);
            }
        }
    }
    return ncr_cacheT[{n, r}];
}

/* B is a distribution matrix for any single variable x1. So B is a identity matrix of dimension k. A is a distribution matrix of form x1x2...xi. This method returns distribution matrix for x1x2...x(i+1)*/
ublas::matrix<int> andCombineT(ublas::matrix<int>& A, ublas::matrix<int>& B, int k){
	int rA = A.size1(); int cA = A.size2();
	int rB = B.size1(); int cB = B.size2();
	int r = rA + rB; int c = cA + cB;
	ublas::matrix<int> C;
	C = ublas::zero_matrix<int>(r, c);
	for(int col = 0; col < k; col++){
		for(int row = 0; row < rA; row++){
			C(row, col) = A(row, col);
			C(row, col + k) = A(row, col);
		}
	}
	for(int col = k; col < 2*k; col++){
		for(int row = rA; row < r; row++){
			C(row, col) = B(row - rA, col - k);
		}
	}
	for(int col = 2*k; col < c; col++){
		for(int row = 0; row < rA; row++){
			C(row, col) = A(row, col - k);
		}
	}
	A.resize(r, c);
	A = C;
	return A;
}

/* B is distribution matrix of t-sized AND form x1x2...xt. A is distribution matrix of OR-ing i number of such x1x2...xt terms. This method returns distribution matrix of OR-ing (i+1) terms of the form x1x2...xt. */
ublas::matrix<int> orCombineT(ublas::matrix<int>& A, ublas::matrix<int>& B, int k){
	int rA = A.size1(); int cA = A.size2();
	int rB = B.size1(); int cB = B.size2();
	int r = rA + rB; int c = cA + cB - k;
	ublas::matrix<int> C;
	C = ublas::zero_matrix<int>(r, c);
	for(int col = 0; col < k; col++){
		for(int row = 0; row < rA; row++){
			C(row, col) = A(row, col);
		}
		for(int row = rA; row < r; row++){
			C(row, col) = B(row - rA, col);
		}
	}
	for(int col = k; col < cA; col++){
		for(int row = 0; row < rA; row++){
			C(row, col) = A(row, col);
		}
	}
	for(int col = cA; col < c; col++){
		for(int row = rA; row < r; row++){
			C(row, col) = B(row - rA, col - cA + k);
		}
	}
	A.resize(r, c);
	A = C;
	return A;
}

/* Build Distribution matrix for OR-ing C(p,t) number of x1x2...xt like terms. */
void buildDistributionMatrix(int t, int k, int p, ublas::matrix<int>& M){
	ublas::matrix<int> M2;
	M2 = ublas::identity_matrix<int>(k);
	ublas::matrix<int> M1;
	M1 = M2;
	for(int i = 2; i <= t; i++){
		M1 = andCombineT(M1, M2, k);
	}
	M = M1;
	for(int i = 2; i <= ncrT(p, t); i++){
		M = orCombineT(M, M1, k);
	}
}

/* rho is a random binary matrix with first k rows coming from the k rows of the secret key */
ublas::matrix<int> buildRho(int k, int p, int e, TLweKey *key, ublas::matrix<int>& rho){
	int N = key->params->N;
	rho = ublas::matrix<int>(e, N);
	for(int row = 0; row < k; row++){
		for(int col = 0; col < N; col++){
			rho(row,col) = key->key[row].coefs[col];
		}
	}
	std::default_random_engine gen;
    std::uniform_int_distribution<int> dist(0, 1);
	for(int row = k; row < e; row++){
		for(int col = 0; col < N; col++){
			rho(row,col) = dist(gen);
		}
	} 
	return rho;
}

/* Naive Matrix Multiplication */
void multiply(ublas::matrix<int>& C, ublas::matrix<int>& A, ublas::matrix<int>& B){
	int r = C.size1(); int c = C.size2();
	for(int row = 0; row < r; row++){
		ublas::matrix_row<ublas::matrix<int>> mrA(A, row);
		for(int col = 0; col < c; col++){
			ublas::matrix_column<ublas::matrix<int>> mcB(B, col);
			C(row,col) = (ublas::inner_prod(mrA,mcB));
		}
	}
}

/* Given a group_id, find the party_ids present in (group_id)^th combination out of C(p,t) combinations */
void findParties(std::vector<int>& pt, int gid, int t, int p){
	int mem = 0, tmp;
	pt.clear();
	for(int i = 1; i < p; i++){
		tmp = ncrT(p - i, t - mem -1);
		if(gid > tmp){
			gid -= tmp;
		}
		else{
			pt.push_back(i);
			mem += 1;
		}
		if(mem + (p-i) == t){
			for(int j = i + 1; j <= p; j++){
				pt.push_back(j);
			}
			break;
		}
	}
}

/* Get and store the actual shares of each party */
void distributeShares(ublas::matrix<int>& S, int t, int k, int p, TLweParams *params){
	int r = S.size1(), N = params->N;
	int row = 1, group_id, row_count;
	std::vector<int> parties;
	while(row <= r){
		group_id = ceil(row/(floor)(k*t));
		findParties(parties, group_id, t, p);
		for(int it = 1; it <= t; it++){
			row_count = row + (it - 1) * k;
			TLweKey *key_share = new_TLweKey(params);
			for(int i = 0; i < k; i++){
				for(int j = 0; j < N; j++){
					key_share->key[i].coefs[j] = S(row_count + i - 1, j);
				}
			}
			shared_key_repo[{parties[it-1], group_id}] = key_share;
		}
		row += (k*t);
	}
}

/* Preprocess to share the secret key among p parties */
void shareSecret(int t, int p, TLweKey *key, TLweParams *params){
	int k = key->params->k;
	int N = key->params->N;

	ublas::matrix<int> M;
	buildDistributionMatrix(t, k, p, M);
	int d = M.size1();
	int e = M.size2();

	ublas::matrix<int> rho;
	rho = buildRho(k, p, e, key, rho);

	ublas::matrix<int> shares(d, N);
	multiply(shares, M, rho);	/* shares = M . rho */

	distributeShares(shares, t, k, p, params);
}

/* Given a t-sized list of party-ids compute its rank among total C(p,t) combinations */
int findGroupId(std::vector<int> parties, int t, int p){
	int mem = 0;
	int group_count = 1;
	for(int i = 1; i <= p; i++){
		if(std::find(parties.begin(), parties.end(), i) != parties.end()){
			mem += 1;
		}
		else{
			group_count += ncrT(p - i, t - mem - 1);
		}
		if(mem == t){
			break;
		}
	}
	return group_count;
}

int thresholdDecrypt(TLweSample *ciphertext, TLweParams* params, std::vector<int> parties, int t, int p, double sd){
	int k = params->k;
	int N = params->N;
	int group_id = findGroupId(parties, t, p);
	TorusPolynomial* acc = new_TorusPolynomial(N);
	for(int i = 0; i < N; i++){
		acc->coefsT[i] = 0;
	}
	for(int i = 0; i < t; i++){
		TorusPolynomial *tmp = new_TorusPolynomial(N);
		for(int j = 0; j < N; j++){
			tmp->coefsT[j] = 0;
		}
		TorusPolynomial *err = new_TorusPolynomial(N);
		for(int j = 0; j < N; j++){
			err->coefsT[j] = gaussian32(0, sd);
		}
		auto part_key = shared_key_repo[{parties[i], group_id}];
		for(int j = 0; j < k; j++){
			torusPolynomialAddMulR(tmp, &part_key->key[j], &ciphertext->a[j]);
			torusPolynomialAddTo(tmp, err);
		}
		if(i == 0){
			torusPolynomialAddTo(acc, tmp);
		}
		else{
			torusPolynomialSubTo(acc, tmp);
		}
	}
	torusPolynomialSub(acc, ciphertext->b, acc);

	Torus32 message = approxPhase(acc->coefsT[0], MSIZE);
	return (message == 0) ? 0 : 1;
}

int main(int argc, char *argv[]){
	if(argc < 4){
		std::cout << "Please provide values of t, p and party-ids of collaborating t parties as space separated integers in the command line for t-out-of-p threshold decryption.\n";
		return 0;
	}
	int t = atoi(argv[1]);
	int p = atoi(argv[2]);
	int party_id;
	std::vector<int> subset;
	for(int i = 3; i < argc; i++){
		party_id = atoi(argv[i]);
		if(party_id <= p)		/* Otherwise, the party id is invalid */
			subset.push_back(atoi(argv[i]));
	}

	/* Check uniqueness and correctness of the provided party-ids */
	std::sort(subset.begin(), subset.end());
	std::vector<int>::iterator it;
	it = std::unique(subset.begin(), subset.end());
	subset.resize(std::distance(subset.begin(), it));
	if(subset.size() < t){
		std::cout << "Please provide at least " << t << " correct and unique party-ids to get result of " << t << "-out-of-" << p << " threshold decrypton.\n";
		return 0;
	}

	/* Read from plaintext file */
	FILE *plaintext = fopen("test/plain22.txt", "r");
    int32_t msg;
    fscanf(plaintext, "%d", &msg);
    fclose(plaintext);
    std::cout << "Plaintext: " << msg <<"\n";

    /* Set Up */
	TLweParams *params = new_TLweParams(1024, 2, 0.01, 0.2);
	TLweKey *key = new_TLweKey(params);
	tLweKeyGen(key);

	std::cout << "tlweKey_param poly degree(N): " <<key->params->N<<"\n";
	std::cout << "tlweKey_param no. of poly(k) : " <<key->params->k<<"\n";
	std::cout << "tlweKey key coefs : " <<key->key[0].coefs[10]<<"\n";
	std::cout << "tlweKey key coefs : " <<key->key[1].coefs[1023]<<"\n";
	std::cout << "tlweKey key N : " <<key->key->N<<"\n";

	/* Encryption */
    TLweSample **ciphertext = new TLweSample*[32];
    for (int i = 0; i < 32; i++){
        ciphertext[i] = new_TLweSample(params);
        // std::cout << "i: " << i << "bit: " << ((msg >> i) & 1) << "\n";
        tLweSymEncryptT(ciphertext[i], modSwitchToTorus32((msg >> i) & 1, MSIZE), 0.001, key);
		
    }

    /* Direct Decryption */
    int dmsg = 0;
    for (int i = 0; i < 32; i++){
        int bit = (tLweSymDecryptT(ciphertext[i], key, MSIZE) == 0) ? 0 : 1;
        dmsg += (bit << i);
    }
    std::cout << "Direct Decryption result: " << dmsg << std::endl;

    /* Threshold Decryption */
    shareSecret(t, p, key, params);


    struct timespec start_time = {0, 0};
    struct timespec end_time = {0, 0};
    
    int rbit;
    int result_msg;
    double bound = 0.5;
    while(bound > 1e-3){
	    result_msg = 0;
	    clock_gettime(CLOCK_MONOTONIC, &start_time);
	    for(int i = 0; i < 32; i++){
	    	rbit = thresholdDecrypt(ciphertext[i], params, subset, t, p, bound);
	    	result_msg += (rbit << i);
	    }
	    clock_gettime(CLOCK_MONOTONIC, &end_time);
	    std::cout << t << "-out-of-" << p << " Threshold Decryption result(with bound " << bound << "): "<< result_msg << ". Decryption Time: " << (((double)end_time.tv_nsec + 1.0e+9 * end_time.tv_sec) - ((double)start_time.tv_nsec + 1.0e+9 * start_time.tv_sec)) * 1.0e-9 << " sec" << std::endl;
	    bound /= 2;
	}
}