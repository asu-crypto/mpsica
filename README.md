

## Installations

### Required libraries
 C++ compiler with C++14 support. There are several library dependencies including [`Boost`](https://sourceforge.net/projects/boost/), [`Miracl`](https://github.com/miracl/MIRACL), [`NTL`](http://www.shoup.net/ntl/) , and [`libOTe`](https://github.com/osu-crypto/libOTe). For `libOTe`, it requires CPU supporting `PCLMUL`, `AES-NI`, and `SSE4.1`. Optional: `nasm` for improved SHA1 performance.   Our code has been tested on Linux (Ubuntu 18.4, corresponding version of g++ and cmake is required on other versions). To install the required libraries: 
  * linux: `cd ./thirdparty`, and `bash all_linux.get`.   

NOTE: If you meet problem with `all_win.ps1` or `all_linux.get` which builds boost, miracl and libOTe, please follow the more manual instructions at [`libOTe`](https://github.com/osu-crypto/libOTe) 

### Building the Project
After cloning project from git,
 
1. make (requirements: `CMake`, `Make`, `g++` or similar)
2. for test:
	./bin/frontend.exe -u

#### Flags:
	-n		number of parties
	-p		party ID
	-m		set size
	-a		run in augmented semihonest model. Table-based OPPRF is by default.
				0: Table-based; 1: POLY-seperated; 2-POLY-combined; 3-BloomFilter
	-r		optimized 3PSI when r = 1			
#### Examples: 
Compute PSI-CA of 4 parties using serverless protocol, each with set size 2^12

	./bin/frontend.exe -m 12 -n 4 -p 0 
	& ./bin/frontend.exe -m 12 -n 4 -p 1
	& ./bin/frontend.exe -m 12 -n 4 -p 2
	& ./bin/frontend.exe -m 12 -n 4 -p 3
	

	
## Summary

      1. git clone https://github.com/asu-crypto/MPSICA.git  
      2. cd thirdparty/
      3. bash all_linux.get 
      4. cd ..
      5. cmake .
      6.  make -j
      7. ./bin/frontend.exe -u
 	
	
## Help
For any questions on building or running the library, please contact [`Jiahui Gao`] at jhgao@asu.edu
