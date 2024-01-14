
#include <iostream>
#include "Network/BtChannel.h"
#include "Network/BtEndpoint.h"

using namespace std;
#include "Common/Defines.h"
using namespace osuCrypto;

#include "bitPosition.h"

#include <numeric>
#include "Common/Log.h"
#include "gbf.h"

#include "psi3.h"




void usage(const char* argv0)
{
	std::cout << "Error! Please use:" << std::endl;
	std::cout << "\t 1. For unit test: " << argv0 << " -u" << std::endl;
	std::cout << "\t 2. For simulation (5 parties <=> 5 terminals): " << std::endl;;
	std::cout << "\t\t each terminal: " << argv0 << " -n 5 -t 2 -m 12 -p [pIdx]" << std::endl;

}
int main(int argc, char** argv)
{

	u64 pSetSize = 5, psiSecParam = 40, bitSize = 128;

	u64 nParties, tParties, opt_basedOPPRF, setSize, isAug, largeSetSizefor2psica;

	u64 roundOPPRF;


	switch (argc) {


	case 5:  //2psi with server-aider
		if (argv[1][0] == '-' && argv[1][1] == 'm')
			setSize = 1 << atoi(argv[2]);
		else
		{
			cout << "setSize: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[3][0] == '-' && argv[3][1] == 'p')
		{
			u64 pIdx = atoi(argv[4]);
			secDotPro(1, 3, pIdx, setSize, setSize, GbfOkvs, secSemiHonest);
		}
		else
		{
			cout << "pIdx: wrong format\n";
			usage(argv[0]);
			return 0;
		}
		break;

	case 7:
		if (argv[1][0] == '-' && argv[1][1] == 'm')
			setSize = 1 << atoi(argv[2]);
		else
		{
			cout << "setSize: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[3][0] == '-' && argv[3][1] == 'n')
			nParties = atoi(argv[4]);
		else if (argv[3][0] == '-' && argv[3][1] == 'M')
			largeSetSizefor2psica = 1<< atoi(argv[4]); 
		else
		{
			cout << "nParties: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[5][0] == '-' && argv[5][1] == 'p')
		{
			u64 pIdx = atoi(argv[6]);
			if (argv[3][1] == 'M')
				secDotPro(1, 3, pIdx, setSize, largeSetSizefor2psica, GbfOkvs, secSemiHonest);
			else
			{
				secDotPro(0, nParties, pIdx, setSize, setSize, GbfOkvs, secSemiHonest);
				//secDotPro(1, nParties, pIdx, setSize, setSize, GbfOkvs, secSemiHonest);
			}
		}
		else
		{
			cout << "pIdx: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		break;

	case 8:
		if (argv[1][0] == '-' && argv[1][1] == 'm')
			setSize = 1 << atoi(argv[2]);
		else
		{
			cout << "setSize: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[3][0] == '-' && argv[3][1] == 'n')
			nParties = atoi(argv[4]);
		else
		{
			cout << "nParties: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[5][0] == '-' && argv[5][1] == 'p' && argv[7][0] == '-' && argv[7][1] == 's')
		{
			u64 pIdx = atoi(argv[6]);
			secDotPro(1, nParties, pIdx, setSize, setSize, GbfOkvs, secSemiHonest);
		}
		else
		{
			cout << "pIdx: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		break;
	}
	return 0;
}
