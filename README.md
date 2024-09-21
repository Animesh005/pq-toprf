# Dev Installation

```bash
git clone <repo url>
cd <repo>
git clone https://github.com/OpenMathLib/OpenBLAS.git
cd OpenBLAS
make
sudo make PREFIX=/usr/local install
cd ..
git clone https://github.com/tfhe/tfhe.git
cd tfhe
make
sudo make install
rm -rf build
cd ..
mkdir bin
make
```

Also install the Boost development library.

We use OpenBLAS (commit a3e80069fb10c830e4de6746e2c9bd27cd4603a9) for efficient linear algebra operations such as matrix multiplications etc.  
And TFHE (commit 2c228a3e1a7a79df09d7d349542ac743227741f0) for Torus-FHE implementation

# Running code

Change `LD_LIBRARY_PATH`:

```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
```
```bash
./bin/toprf_eval t T flag
```
Here, (t, T) denotes t-out-of-T threshold access structure and flag denotes type of threshold decryption. If flag is 1 then it performs the LISSS secret sharing and if flag is 0 it performs an Additive secret sharing
