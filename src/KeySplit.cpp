#include <bits/stdc++.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#define P 8191

using namespace std;

int32_t mod_exp(int32_t x, unsigned int pow)
{
    long long ans = 1;

    while (pow > 0){
        if (pow % 2 == 1)
            ans = (ans * x) % P;
        x = (x * x) % P;
        pow = (pow >> 1);
    }

    return (int32_t)((ans + P) % P);
}

int32_t inv_mod(int32_t x)
{
    // x ^ (P - 2) % P
    return mod_exp(x, P - 2);
}

struct Polynomial
{
    int32_t *coeffs;
    int n;
    Polynomial(int n);
    int32_t Eval(int32_t x);
};

struct Shard
{
    int t, n;
    int32_t x, f;
    Shard(int t, int n, int32_t x, int32_t f)
        :t(t), n(n), x(x), f(f)
    {}
    
    Shard()
    {}
};

Polynomial::Polynomial(int n)
    :n(n)
{
    coeffs = new int32_t[n + 1];
}

int32_t Polynomial::Eval(int32_t x)
{
    int32_t ans = 0, buff = 1;
    for (int i = 0; i <= n; i++){
        ans += (coeffs[i] * buff) % P;
        buff = (buff * x) % P;
    }

    return ((ans + 5 * P) % P);
}

/* Shamir's secret sharing naive implementation */
Shard* SplitSecret(int32_t secret, int t, int n)
{
    Polynomial *sp = new Polynomial(t - 1);

    // We will randomly fill up the coefficients using elements of Z_P
    // Only the constant term is the secret
    sp->coeffs[0] = secret;
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int32_t> dist(1, P - 1);
    for (int i = 1; i <= t; i++){
        sp->coeffs[i] = dist(gen);
    }

    // Now we will choose distinct n numbers in Z_P for the shares
    set<int32_t> xs;
    while (xs.size() < n){
        xs.insert(dist(gen));
    }

    Shard *shards = new Shard[n];
    int i = 0;
    for (int32_t x : xs){
        shards[i] = Shard(t, n, x, sp->Eval(x));
        i++;
    }

    delete sp;
    return shards;
}

int32_t ReconstructSecret(Shard* shards)
{
    // Assume at least one element is present
    int t = shards[0].t;
    int n = shards[0].n;

    int32_t secret = 0;

    // Lagrange Interpolation
    for (int i = 0; i < t; i++){    // Only t shares are needed, so we take the first t
        int32_t pdt = shards[i].f;
        for (int j = 0; j < t; j++){
            if (i != j){
                pdt = (pdt * -shards[j].x) % P;
                pdt = (pdt * inv_mod(shards[i].x - shards[j].x)) % P;
            }
        }
        secret = (secret + pdt + 5 * P) % P;
    }

    return secret;
}

void SplitTfheKeyFile(string fname, int t, int n)
{
    FILE *keyfile = fopen(fname.c_str(), "rb");
    auto key = new_tfheGateBootstrappingSecretKeySet_fromFile(keyfile);
    fclose(keyfile);

    int rows = key->lwe_key->params->n;
    Shard **shards = new Shard*[rows];
    for (int i = 0; i < rows; i++){
        shards[i] = SplitSecret(key->lwe_key->key[i], t, n);
        key->lwe_key->key[i] = 0;           // Common part to be sent with the shard
    }

    // Save n files with name fname_shards/part_i.key
    for (int i = 0; i < n; i++){
        string partname = fname + "_shards/part_" + to_string(i) + ".key";
        FILE *part = fopen(partname.c_str(), "w");
        fprintf(part, "%d %d %d\n", rows, t, n);
        for (int j = 0; j < rows; j++){
            fprintf(part, "%d %d\n", shards[j][i].x, shards[j][i].f);
        }
        fclose(part);
    }

    // Save the common part
    string commonname = fname + "_shards/common.key";
    FILE *common = fopen(commonname.c_str(), "wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(common, key);
    fclose(common);

}

void ReconstructTfheKeyFile(string fname, int numkeys)
{
    // Atleast 1 shard file is expected
    string shardname = fname + "_shards/part_0.key";
    FILE *f = fopen(shardname.c_str(), "r");
    int rows, t, n;
    fscanf(f, "%d %d %d", &rows, &t, &n);
    cout << rows << " " << t << " " << n << " " << numkeys << endl;
    // t <= numkeys <= n
    fclose(f);
    Shard **shards = new Shard*[rows];
    for (int i = 0; i < rows; i++){
        shards[i] = new Shard[numkeys];
        for (int j = 0; j < n; j++){
            shards[i][j].t = t;
            shards[i][j].n = numkeys;
        }
    }

    int bufft, buffn, buffrows;
    int32_t x, val;

    for (int i = 0; i < numkeys; i++){
        string partname = fname + "_shards/part_" + to_string(i) + ".key";
        FILE *shardfile = fopen(partname.c_str(), "r");
        fscanf(shardfile, "%d %d %d", &buffrows, &bufft, &buffn);
        for (int j = 0; j < rows; j++){
            fscanf(shardfile, "%d %d", &x, &val);
            shards[j][i].f = val;
            shards[j][i].x = x;
        }

        fclose(shardfile);
    }

    string commonname = fname + "_shards/common.key";
    FILE *common = fopen(commonname.c_str(), "rb");
    auto key = new_tfheGateBootstrappingSecretKeySet_fromFile(common);
    fclose(common);

    for (int i = 0; i < rows; i++){
        key->lwe_key->key[i] = ReconstructSecret(shards[i]);
    }

    string reconstructname = fname + "_shards/reconstruct.key";
    FILE *rec = fopen(reconstructname.c_str(), "wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(rec, key);
    fclose(rec);
}

int main()
{
    SplitTfheKeyFile("test/secret.key", 2, 3);
    ReconstructTfheKeyFile("test/secret.key", 3);
    return 0;
}

