#pragma once
#include "Crypto/PRNG.h"
#include "Common/Defines.h"
#include "Common/Log.h"
#include "Common/Log1.h"
#include <set>
#include "gbf.h"
#include <fstream>
#include <util.h>
#include "Network/Channel.h"
#include "Network/BtEndpoint.h"
#include "NChooseOne/KkrtNcoOtReceiver.h"
#include "NChooseOne/KkrtNcoOtSender.h"
#include "OPPRF/OPPRFReceiver.h"
#include "OPPRF/OPPRFSender.h"
#include <Common/ByteStream.h>

using namespace osuCrypto;

//Protocol 10
inline void sec2DotPro(u64 myIdx,  const std::vector<std::vector<Channel*>> chls, u64 largeSetSize, const std::vector<block>& inputSet, u64 type_okvs, u64 type_security, bool isTimerReset = 1) {


#pragma region setup
     	u64 setSize = inputSet.size(), psiSecParam = 40, bitSize = 128, okvsTableSize = setSize;
		Timer timer;
		PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx));
		std::vector<u32> mIntersection;

		u64 maskSize = roundUpTo(psiSecParam + 2 * std::log2(setSize) - 1, 8) / 8;
		PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045)), prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));


		if (isTimerReset) //for nparty 
		{
			timer.reset();
			auto start = timer.setTimePoint("start");
		}

		std::vector <block> aesKeys(2); // for party 1 and 2

		int consistCheckSize = 0;
		if (type_security == secMalicious)
			consistCheckSize = securityParameter; //size of consistancy check set

		int newSetSize = setSize + consistCheckSize;
		int newLargeSetSize = largeSetSize + consistCheckSize;

		if (type_okvs == GbfOkvs)
			okvsTableSize = newLargeSetSize * okvsLengthScale;
		else if (type_okvs == PolyOkvs)
			okvsTableSize = newLargeSetSize;

		std::vector<std::vector<block>> PRF_values(2); //for party 1 and 2 to compute F(k, a)
		PRF_values[0].resize(newSetSize);
		PRF_values[1].resize(newLargeSetSize);

		std::vector<block> set_V(newLargeSetSize), set_A(consistCheckSize), set_B(consistCheckSize);

		for (int i = 0; i < newLargeSetSize; i++) //generate V for party 1 and 2
			set_V[i] = prngSame.get<block>(); //set_B is the last consistCheckSize items of set_V

		if (type_security == secMalicious)
			for (int i = 0; i < set_A.size(); i++) //generate consistency (A,B) for party 1 and 2
				set_A[i] = prngSame.get<block>();

#pragma endregion


		if (myIdx == 0) //Receiver
		{	

			//receiving aes key from part sender
			chls[1][0]->recv(&aesKeys[0], sizeof(block));

			AES party0_AES(aesKeys[0]);
			party0_AES.ecbEncBlocks(inputSet.data(), inputSet.size(), PRF_values[0].data()); //compute F_ki(xi)

			chls[2][0]->send(PRF_values[0].data(), PRF_values[0].size() * sizeof(block)); //send pi(F_ki(xi)) to server (party 3)

			chls[1][0]->recv(set_V.data(), set_V.size() * sizeof(block)); // receive pi(F_k(x)) from sender
			std::vector<block> set_W(newSetSize);
			chls[2][0]->recv(set_W.data(), set_W.size() * sizeof(block)); // receive pi(F_k(y)) from server


			//generate localMasks for computing the intersection
			std::unordered_map<u64, std::pair<block, u64>> localMasks;
			for (u32 i = 0; i < set_V.size(); i++) //create an unordered_map for recv_ciphertexts[0]
				localMasks.emplace(*(u64*)&set_V[i], std::pair<block, u64>(set_V[i], i));

			//===============compute the set intersection size
			for (int i = 0; i < set_W.size(); i++) //for each item in recv_ciphertexts[1], we check it in localMasks
			{
				u64 shortcut;
				memcpy((u8*)&shortcut, (u8*)&set_W[i], sizeof(u64));
				auto match = localMasks.find(shortcut);

				//if match, check for whole bits
				if (match != localMasks.end())
				{
					if (memcmp((u8*)&set_W[i], &match->second.first, sizeof(block)) == 0) // check full mask
					{
						mIntersection.push_back(match->second.second);
					}
				}
			}

		}

		else if (myIdx == 1) //Sender
		{
			
			//generating aes key and sends it to receiver
			aesKeys[0] = prng.get<block>();
			chls[0][0]->send(&aesKeys[0], sizeof(block)); //sending aesKeys_party1 to party 2 (idx=1)
			//generating aes key and sends it to server
			aesKeys[1] = prng.get<block>();
			chls[2][0]->send(&aesKeys[1], sizeof(block)); //sending aesKeys_party1 to party 2 (idx=1)


			AES party1_AES0(aesKeys[0]);
			party1_AES0.ecbEncBlocks(inputSet.data(), inputSet.size(), PRF_values[0].data()); //compute F_k0(xi)
			AES party1_AES1(aesKeys[1]);
			party1_AES1.ecbEncBlocks(PRF_values[0].data(), PRF_values[0].size(), PRF_values[1].data()); //compute F_k(xi)

			// send F(k,x) to recerver
			chls[0][0]->send(PRF_values[1].data(), PRF_values[1].size() * sizeof(block)); 

			

		}
		else if (myIdx == 2) //Server
		{
			// receiving aes key from part sender
			chls[1][0]->recv(&aesKeys[1], sizeof(block));
			std::vector<block> recv_ciphertexts(newSetSize); //for server to receive pi(F(k, a)) form receiver

			chls[0][0]->recv(recv_ciphertexts.data(), recv_ciphertexts.size() * sizeof(block)); // receive pi(F_ki(xi)) from receiver

			AES party2_AES(aesKeys[1]);
			party2_AES.ecbEncBlocks(recv_ciphertexts.data(), recv_ciphertexts.size(), PRF_values[1].data()); //compute F_ki(xi)

			// send F(k,y) to recerver
			chls[0][0]->send(PRF_values[1].data(), PRF_values[1].size() * sizeof(block));

			
		}

		auto end = timer.setTimePoint("end");

		if (isTimerReset) //for nparty 
		{
			std::cout << IoStream::lock;
			std::cout << "party #" << myIdx << "\t" << timer << std::endl;
			if (myIdx == 0)
				Log::out << "mIntersection.size(): " << mIntersection.size() - consistCheckSize << Log::endl;
			std::cout << IoStream::unlock;
		}
		
	}

//Protocol 11
inline void secnDotPro_server_aided(u64 nParties, u64 myIdx, const std::vector<std::vector<Channel*>> chls, const std::vector<block>& inputSet, u64 type_okvs, u64 type_security) {


	//std::cout << IoStream::lock;
	//std::cout << "inside myIdx: " << myIdx << std::endl;
	//std::cout << IoStream::unlock;

#pragma region setup
	u64 setSize = inputSet.size(), psiSecParam = 40, bitSize = 128, okvsTableSize = setSize;
	Timer timer;
	PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx));
	std::vector<u32> mIntersection;
	

	u64 maskSize = roundUpTo(psiSecParam + 2 * std::log2(setSize) - 1, 8) / 8;
	PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045)), prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));

	timer.reset();
	auto start = timer.setTimePoint("start");
	block aesKeyAll; // computing F(k, input) for all parties

	int consistCheckSize = 0;
	if (type_security == secMalicious)
	{
		consistCheckSize = securityParameter; //size of consistancy check set
	}
	int newSetSize = setSize + consistCheckSize;

	std::vector<block> newInputSet(newSetSize);
	std::vector<block> set_A(consistCheckSize);

	for (int i = 0; i < set_A.size(); i++) //generate consistency (A,B) for party 1 and 2
	{
		set_A[i] = prngSame.get<block>();
	}

	memcpy(newInputSet.data(), inputSet.data(), inputSet.size() * sizeof(block));
	memcpy(newInputSet.data() + inputSet.size(), set_A.data(), set_A.size() * sizeof(block));

	if (type_okvs == GbfOkvs)
		okvsTableSize = newSetSize * okvsLengthScale;
	else if (type_okvs == PolyOkvs)
		okvsTableSize = newSetSize;

	std::vector<block> PRF_values(newSetSize);

	std::vector<block> set_gamma(newSetSize);
	for (int i = 0; i < set_gamma.size(); i++) 
		set_gamma[i] = prngSame.get<block>(); 



	std::vector <block> zeroShares(newInputSet.size(), ZeroBlock); //[i][] for party i

	if (myIdx > 1) //generate zerosharing key among party 2-n
	{
		std::vector <std::vector<AES>> zeroShareKeys(nParties); //[i][] for party i
		for (int i = 2; i < zeroShareKeys.size(); i++) //start from party 2 (not party 1)
		{
			zeroShareKeys[i].resize(nParties);
			for (int j = 2; j < zeroShareKeys[i].size(); j++)
			{
				if (i < j)
					zeroShareKeys[i][j].setKey(prngSame.get<block>());
				else
					zeroShareKeys[i][j] = zeroShareKeys[j][i];
			}
		}

		//compute zeroXOR

		std::vector <block> tempt(newInputSet.size(), ZeroBlock); //[i][] for party i
		for (int i = 2; i < nParties; i++)
			if (i != myIdx)
			{
				zeroShareKeys[myIdx][i].ecbEncBlocks(inputSet.data(), inputSet.size(), tempt.data()); //compute F_kij(xi)		
				for (int j = 0; j < inputSet.size(); j++)
					zeroShares[j] = zeroShares[j] ^ tempt[j]; //xor all F_kij(x)
			}
			
		//for (int j = 0; j < inputSet.size(); j++)
			//zeroShares[j] = ZeroBlock;
	}

	if (myIdx == 0) //server
	{
		std::vector <std::vector<block>> recv_okvsTable(nParties); //for server to receive okvsTable from each party (except p0)
		std::vector < std::vector<block>> OKVS_decodes(nParties);
		std::vector <block> recv_PRF_value1(newInputSet.size());
		std::vector <block> set_W(newInputSet.size(), ZeroBlock);

		chls[1][0]->recv(recv_PRF_value1.data(), recv_PRF_value1.size() * sizeof(block)); //receive PRF value from party 1


		std::vector<std::thread>  pThrds(nParties); //for each channel that communicates with party i

		for (u64 i = 2; i < pThrds.size(); ++i)
		//for (u64 i = 2; i < nParties; i++)
		{
			pThrds[i] = std::thread([&, i]() {

			recv_okvsTable[i].resize(okvsTableSize);
			OKVS_decodes[i].resize(newInputSet.size());

			chls[i][0]->recv(recv_okvsTable[i].data(), recv_okvsTable[i].size() * sizeof(block)); //receive okvs table


			if (type_okvs == GbfOkvs) //Decode OKVS for Pi's input
				GbfDecode(recv_okvsTable[i], recv_PRF_value1, OKVS_decodes[i]);
			else if (type_okvs == PolyOkvs)
				PolyDecode(recv_okvsTable[i], recv_PRF_value1, OKVS_decodes[i]);

		


	 //simulate the cost of oprf
			if (setSize== (1 << 12)) //set size =2^12
				this_thread::sleep_for(chrono::milliseconds(211));
			else if (setSize== (1 << 16)) //set size =2^16
				this_thread::sleep_for(chrono::milliseconds(387));
			else if (setSize == (1 << 20)) //set size =2^16
				this_thread::sleep_for(chrono::milliseconds(3780));
			else
				this_thread::sleep_for(chrono::milliseconds(3780*(setSize/(1<<20))));
			//std::cout << IoStream::lock;
			//std::cout << OKVS_decodes[i][0] << " \t" << i << " OKVS_decodes\n";
			//std::cout << IoStream::unlock;
				});
		}

		for (u64 pIdx = 2; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();

		for (u64 i = 2; i < nParties; i++)
			for (u64 j = 0; j < newInputSet.size(); j++) {
				set_W[j] = set_W[j] ^ OKVS_decodes[i][j];
			}

		

		chls[1][0]->send(set_W.data(), set_W.size() * sizeof(block));

	}
	else if (myIdx == 1) //P1
	{	//generate random key and send to other party
		aesKeyAll = prng.get<block>();
		for (int i = 2; i < nParties; i++)
			chls[i][0]->send(&aesKeyAll, sizeof(block));
		


		AES party_AES(aesKeyAll);
		party_AES.ecbEncBlocks(newInputSet.data(), newInputSet.size(), PRF_values.data()); //compute F_ki(xi)		
		//shuffle(PRF_values.begin(), PRF_values.end(), prng);
		chls[0][0]->send(PRF_values.data(), PRF_values.size() * sizeof(block)); //send pi(F_ki(xi)) to server (party 3)

		std::vector <block> recv_set_W(newInputSet.size(), ZeroBlock);
		chls[0][0]->recv(recv_set_W.data(), recv_set_W.size() * sizeof(block));

		std::unordered_map<u64, std::pair<block, u64>> localMasks;
		for (u32 i = 0; i < newSetSize; i++) //create an unordered_map for recv_ciphertexts[0]
		{
			localMasks.emplace(*(u64*)&recv_set_W[i], std::pair<block, u64>(recv_set_W[i], i));
		}

		for (int i = 0; i < newSetSize; i++) //for each item in recv_ciphertexts[1], we check it in localMasks
		{
			u64 shortcut;
			memcpy((u8*)&shortcut, (u8*)&set_gamma[i], sizeof(u64));
			auto match = localMasks.find(shortcut);

			//if match, check for whole bits
			if (match != localMasks.end())
			{
				if (memcmp((u8*)&set_gamma[i], &match->second.first, sizeof(block)) == 0) // check full mask
				{
					mIntersection.push_back(match->second.second);
				}
			}
		}
		
	}
	else if (myIdx == 2)	//P2
	{
		chls[1][0]->recv(&aesKeyAll, sizeof(block));

		AES party_AES(aesKeyAll);
		party_AES.ecbEncBlocks(newInputSet.data(), newInputSet.size(), PRF_values.data()); //compute PRF(k,x)
		
		std::vector<block> set_v2(set_gamma.size(), ZeroBlock);
		for (int i = 0; i < set_gamma.size(); i++) {
			set_v2[i] = set_gamma[i] ^ zeroShares[i];
		}

		std::vector<block> okvsTable(okvsTableSize);
		if (type_okvs == GbfOkvs)
			GbfEncode(PRF_values, set_v2, okvsTable);
		else if (type_okvs == PolyOkvs)
			PolyEncode(PRF_values, set_v2, okvsTable);

			 //simulate the cost of oprf
			if (setSize== (1 << 12)) //set size =2^12
				this_thread::sleep_for(chrono::milliseconds(211));
			else if (setSize== (1 << 16)) //set size =2^16
				this_thread::sleep_for(chrono::milliseconds(387));
			else if (setSize == (1 << 20)) //set size =2^16
				this_thread::sleep_for(chrono::milliseconds(3780));
			else
				this_thread::sleep_for(chrono::milliseconds(3780*(setSize/(1<<20))));

		chls[0][0]->send(okvsTable.data(), okvsTable.size() * sizeof(block)); // send OKVS table to server


	}
	else if (myIdx > 2)
	{
		chls[1][0]->recv(&aesKeyAll, sizeof(block));

		AES party_AES(aesKeyAll);
		party_AES.ecbEncBlocks(newInputSet.data(), newInputSet.size(), PRF_values.data()); //compute PRF(k,x)

		std::vector<block> okvsTable(okvsTableSize);
		if (type_okvs == GbfOkvs)
			GbfEncode(PRF_values, zeroShares, okvsTable);
		else if (type_okvs == PolyOkvs)
			PolyEncode(PRF_values, zeroShares, okvsTable);

			 //simulate the cost of oprf
			if (setSize== (1 << 12)) //set size =2^12
				this_thread::sleep_for(chrono::milliseconds(211));
			else if (setSize== (1 << 16)) //set size =2^16
				this_thread::sleep_for(chrono::milliseconds(387));
			else if (setSize == (1 << 20)) //set size =2^16
				this_thread::sleep_for(chrono::milliseconds(3780));
			else
				this_thread::sleep_for(chrono::milliseconds(3780*(setSize/(1<<20))));

		chls[0][0]->send(okvsTable.data(), okvsTable.size() * sizeof(block)); // send OKVS table to server


	}
	auto end = timer.setTimePoint("end");

	std::cout << IoStream::lock;
	std::cout << "party #"<<myIdx<<"\t" << timer << std::endl;

	if (myIdx == 1)
		Log::out << "mIntersection.size(): " << mIntersection.size() << Log::endl;
	std::cout << IoStream::unlock;


}


// Protocol 12
inline void secnDotPro(u64 nParties, u64 myIdx, const std::vector<std::vector<Channel*>> chls, const std::vector<block>& inputSet, u64 type_okvs, u64 type_security) {


	

#pragma region setup
		u64 setSize = inputSet.size(), psiSecParam = 40, bitSize = 128, okvsTableSize = setSize;
		Timer timer;
		PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx));
		std::vector<u32> mIntersection;

		u64 maskSize = roundUpTo(psiSecParam + 2 * std::log2(setSize) - 1, 8) / 8;
		PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045)), prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));

		

		timer.reset();
		auto start = timer.setTimePoint("start");
		block aesKeyAll; // computing F(k, input) for all parties
		block aesKey01; // computing F(k, value) for p1 and p2 only

		if (type_okvs == GbfOkvs)
			okvsTableSize = setSize * okvsLengthScale;
		else if (type_okvs == PolyOkvs)
			okvsTableSize = setSize;


#pragma endregion

#pragma region ZeroShare 
//simulation: NOTE: generate zeroshare key for only party 2--->n

		//aesKeyAll = prngSame.get<block>();
		//aesKey01 = prngSame.get<block>();
		std::vector<block> PRF_values(setSize); // compute F(k, x)

		std::vector <block> zeroShares(inputSet.size(), ZeroBlock); //[i][] for party i

		if (myIdx != 0)
		{
			std::vector <std::vector<AES>> zeroShareKeys(nParties); //[i][] for party i
			for (int i = 1; i < zeroShareKeys.size(); i++) //start from party 2 (not party 1)
			{
				zeroShareKeys[i].resize(nParties);
				for (int j = 1; j < zeroShareKeys[i].size(); j++)
				{
					if (i < j)
						zeroShareKeys[i][j].setKey(prngSame.get<block>());
					else
						zeroShareKeys[i][j] = zeroShareKeys[j][i];
				}
			}

			//compute zeroXOR

			std::vector <block> tempt(inputSet.size(), ZeroBlock); //[i][] for party i
			for (int i = 1; i < nParties; i++)
				if (i != myIdx)
				{
					zeroShareKeys[myIdx][i].ecbEncBlocks(inputSet.data(), inputSet.size(), tempt.data()); //compute F_kij(xi)		
					for (int j = 0; j < inputSet.size(); j++)
						zeroShares[j] = zeroShares[j] ^ tempt[j]; //xor all F_kij(x)
				}

			//for (int j = 0; j < inputSet.size(); j++)
			//	zeroShares[j] = ZeroBlock;
		}
#pragma endregion


		if (myIdx == 0) //P1
		{
			  
			//generating aes key and sends it to p2 only
			aesKey01 = prng.get<block>();
			chls[2][0]->send(&aesKey01, sizeof(block));

			AES party_AES(aesKey01);
			party_AES.ecbEncBlocks(inputSet.data(), inputSet.size(), PRF_values.data()); //compute F_ki(xi)

			std::vector<std::thread>  pThrds(nParties); //for each channel that communicates with party i
			for (u64 i = 2; i < pThrds.size(); ++i)
			{	
				//=========== SOPPRF===============
				// reveive k2 from p2
				block k2_received;
				chls[i][0]->recv(&k2_received, sizeof(block));
				// receive F(k1,xn) from pn
				std::vector<block> recv_okvs_key(PRF_values.size());
				chls[1][0]->recv(recv_okvs_key.data(), recv_okvs_key.size() * sizeof(block)); 
				// send F(k,xn) to pn
				AES okvs_AES2(k2_received);
				okvs_AES2.ecbEncBlocks(recv_okvs_key.data(),recv_okvs_key.size(),recv_okvs_key.data());
				chls[1][0]->send(recv_okvs_key.data(), recv_okvs_key.size() * sizeof(block)); 
			}

			sec2DotPro(myIdx, chls, PRF_values.size(), PRF_values, GbfOkvs, secMalicious, 0); //2psica

		}
		else if (myIdx == 1) //Pn
		{
			chls[2][0]->recv(&aesKeyAll, sizeof(block));
			AES party_AES(aesKeyAll);
			party_AES.ecbEncBlocks(inputSet.data(), inputSet.size(), PRF_values.data()); //compute F_ki(xi)	

			std::vector <std::vector<block>> recv_okvsTable(nParties); //for server to receive okvsTable from each party (except p0)
			std::vector < std::vector<block>> OKVS_decodes(nParties);

			std::vector <std::vector<block>> okvs_keys(nParties,std::vector<block>(PRF_values.size()));
			
			std::vector<std::thread>  pThrds(nParties); //for each channel that communicates with party i

#if 1
			for (u64 i = 2; i < pThrds.size(); ++i)
			{	
			//=========== SOPPRF===============
				// receive  k1 from p2
				block k1_received;
				chls[i][0]->recv(&k1_received, sizeof(block));
				// send F(k1,xn) to p1			
				AES okvs_AES1(k1_received);
				okvs_AES1.ecbEncBlocks(PRF_values.data(),PRF_values.size(),okvs_keys[i].data());
				chls[0][0]->send(okvs_keys[i].data(), okvs_keys[i].size() * sizeof(block)); 

				// receive F(k,xn) from p1
				std::vector<block> recv_okvs_key(PRF_values.size());
				chls[0][0]->recv(recv_okvs_key.data(), recv_okvs_key.size() * sizeof(block));

				//receive okvs from p2
				pThrds[i] = std::thread([&, i]() {
				recv_okvsTable[i].resize(okvsTableSize);
				OKVS_decodes[i].resize(inputSet.size());

				chls[i][0]->recv(recv_okvsTable[i].data(), recv_okvsTable[i].size() * sizeof(block)); //receive okvs table

				if (type_okvs == GbfOkvs) //Decode OKVS for Pi's input
					GbfDecode(recv_okvsTable[i], recv_okvs_key, OKVS_decodes[i]);
				else if (type_okvs == PolyOkvs)
					PolyDecode(recv_okvsTable[i], recv_okvs_key, OKVS_decodes[i]);


					});
			}

			for (u64 pIdx = 2; pIdx < pThrds.size(); ++pIdx)
				pThrds[pIdx].join();


			for (int i = 2; i < nParties; i++)
				for (int j = 0; j < zeroShares.size(); j++)
				{
					zeroShares[j] = zeroShares[j] ^ OKVS_decodes[i][j];
				}
#endif

		/*	std::cout << IoStream::lock;
			std::cout << zeroShares[0] << " \t" << " before 2psica 2\n";
			std::cout << IoStream::unlock;*/

			sec2DotPro(myIdx, chls, PRF_values.size(), zeroShares, GbfOkvs, secMalicious,0); //2psica
			
			
		}

		if (myIdx == 2) //P2
		{
			//generating aes key and sends it to all other parties
			aesKeyAll = prng.get<block>();
			chls[1][0]->send(&aesKeyAll, sizeof(block));
			for (int i = 3; i < nParties; i++)
				chls[i][0]->send(&aesKeyAll, sizeof(block));


			chls[0][0]->recv(&aesKey01, sizeof(block));

			AES party_AES(aesKeyAll);
			std::vector<block> PRF_values(setSize); // compute F(k, x)
			party_AES.ecbEncBlocks(inputSet.data(), inputSet.size(), PRF_values.data()); //compute F_ki(xi)	

#if 1
			std::vector<block> valueOKVS(setSize); 
			party_AES.setKey(aesKey01);
			party_AES.ecbEncBlocks(inputSet.data(), inputSet.size(), valueOKVS.data()); //compute F_ki(xi)	

			/*std::cout << IoStream::lock;
			std::cout << PRF_values[0] << " \t" << myIdx << "\t all \n";
			std::cout << valueOKVS[0] << " \t" << myIdx << "\t 01 \n";
			std::cout << IoStream::unlock;*/

			for (int i = 0; i < valueOKVS.size(); i++) {
				valueOKVS[i] = valueOKVS[i] ^ zeroShares[i];
			}
			
			//sopprf
			// send k1 k2 to pn p1
			block k1 = prng.get<block>();
			block k2 = prng.get<block>();
			chls[1][0]->send(&k1, sizeof(block));
			chls[0][0]->send(&k2, sizeof(block));
			// modify the okvs_key
			vector<block> okvs_key(PRF_values.size());
			AES okvs_AES1(k1);
			AES okvs_AES2(k2);
			okvs_AES1.ecbEncBlocks(PRF_values.data(),PRF_values.size(),okvs_key.data());
			okvs_AES2.ecbEncBlocks(okvs_key.data(),okvs_key.size(),okvs_key.data());

			// send okvs to pn
			std::vector<block> okvsTable(okvsTableSize);
			if (type_okvs == GbfOkvs)
				GbfEncode(okvs_key, valueOKVS, okvsTable);
			else if (type_okvs == PolyOkvs)
				PolyEncode(okvs_key, valueOKVS, okvsTable);
#endif
			//sending OKVS table to Pn 
			chls[1][0]->send(okvsTable.data(), okvsTable.size() * sizeof(block)); // send OKVS table to server 

			std::vector<block> empty(setSize,ZeroBlock);
			sec2DotPro(myIdx, chls, PRF_values.size(), empty, GbfOkvs, secMalicious,0); //play a role of server in 2psica
		}
#if 1
		else if (myIdx>2) //for party 3->n-1
		{
			chls[2][0]->recv(&aesKeyAll, sizeof(block));
			AES party_AES(aesKeyAll);
			party_AES.ecbEncBlocks(inputSet.data(), inputSet.size(), PRF_values.data()); //compute F_ki(xi)	


			//sopprf
			// send k1 k2 to pn p1
			block k1 = prng.get<block>();
			block k2 = prng.get<block>();
			chls[1][0]->send(&k1, sizeof(block));
			chls[0][0]->send(&k2, sizeof(block));
			// modify the okvs_key
			vector<block> okvs_key(PRF_values.size());
			AES okvs_AES1(k1);
			AES okvs_AES2(k2);
			okvs_AES1.ecbEncBlocks(PRF_values.data(),PRF_values.size(),okvs_key.data());
			okvs_AES2.ecbEncBlocks(okvs_key.data(),okvs_key.size(),okvs_key.data());

			// send okvs to pn
			std::vector<block> okvsTable(okvsTableSize);
			if (type_okvs == GbfOkvs)
				GbfEncode(okvs_key, zeroShares, okvsTable);
			else if (type_okvs == PolyOkvs)
				PolyEncode(okvs_key, zeroShares, okvsTable);

			chls[1][0]->send(okvsTable.data(), okvsTable.size() * sizeof(block)); // send OKVS table to server (party 3)
		}
#endif	
		auto end = timer.setTimePoint("end");

		std::cout << IoStream::lock;
		std::cout << "party #" << myIdx << "\t" << timer << std::endl;
		std::cout << IoStream::unlock;

		
}


//function for calling the corresponding protocols
inline void secDotPro(bool isServerAided, u64 nParties, u64 myIdx, u64 setSize, u64 largeSetSize, u64 type_okvs, u64 type_security) {
	u64 numChannelThreads = 1, expected_intersection = rand() % setSize;


	if (myIdx == 0)
	{
		std::cout << IoStream::lock;
		std::cout << "================="<<std::endl;
		std::cout << IoStream::unlock;
	}

#pragma region setup
	std::string name("psi");
	BtIOService ios(0);
	std::vector<BtEndpoint> ep(nParties);
	std::vector<std::vector<Channel*>> chls(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			u32 port = 1200 + i * 100 + myIdx;;//get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
		}
		else if (i > myIdx)
		{
			u32 port = 1200 + myIdx * 100 + i;//get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
		}
	}


	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx) {
			chls[i].resize(numChannelThreads);
			for (u64 j = 0; j < numChannelThreads; ++j)
				chls[i][j] = &ep[i].addChannel(name, name);
		}
	}



	PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045)), prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));
	std::vector<block> inputSet(setSize);

	if (largeSetSize > setSize && myIdx == 1) //sender for 2psica
		inputSet.resize(largeSetSize);

		for (u64 i = 0; i < expected_intersection; ++i)
			inputSet[i] = prngSame.get<block>();

		for (u64 i = expected_intersection; i < setSize; ++i)
			inputSet[i] = prngDiff.get<block>();

		if (largeSetSize != setSize && myIdx == 1) //sender for 2psica
			for (u64 i = setSize; i < largeSetSize; ++i)
				inputSet[i] = prngDiff.get<block>();

	
	
#pragma endregion

	block temp = prngSame.get<block>(); //reset network
	for (int i = 0; i < nParties; i++)
	{
		if (i != myIdx)
		{
			chls[i][0]->send(&temp, sizeof(block));
			chls[i][0]->recv(&temp, sizeof(block));
		}
	}

	if (myIdx == 0)
	{
		if (type_security == secSemiHonest)
		{
			std::cout << "secSemiHonest " << std::endl;
		}
		else
		{
			std::cout << "secMalicious " << std::endl;
		}
	}

	if (nParties == 3 && isServerAided)
	{
		if (myIdx == 0)
		{
			std::cout << IoStream::lock;
			std::cout << "sec2DotPro: " << setSize << " \t" <<largeSetSize <<"\t" << nParties << std::endl;
			std::cout << IoStream::unlock;
		}

		sec2DotPro(myIdx,  chls, largeSetSize, inputSet, type_okvs, type_security);
	}
	else if (nParties > 3 && isServerAided) {
			if (myIdx == 0)
			{
				std::cout << IoStream::lock;
				std::cout << "secnDotPro_server_aided: " << setSize << " \t" << nParties << std::endl;
				std::cout << IoStream::unlock;
			}

			secnDotPro_server_aided(nParties, myIdx, chls, inputSet, type_okvs, type_security);
	}
	else if (nParties > 2 && !isServerAided) {
			if (myIdx == 0)
			{
				std::cout << IoStream::lock;
				std::cout << "secNDotPro: " << setSize << " \t" << nParties << std::endl;
				std::cout << IoStream::unlock;
			}
			secnDotPro(nParties, myIdx, chls, inputSet, type_okvs, type_security);
	}
	
	//if (myIdx == 0)
	//{
	//	std::cout << IoStream::lock;
	//	std::cout << "expected_intersection: " << expected_intersection << std::endl;
	//	std::cout << IoStream::unlock;
	//}


	for (int i = 0; i < nParties; i++)
	{
		if (i != myIdx)
		{
			chls[i][0]->send(&temp, sizeof(block));
			chls[i][0]->recv(&temp, sizeof(block));
		}
	}

	double dataSent = 0, dataRecv = 0, Mbps = 0, MbpsRecv = 0;
	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx) {
			//chls[i].resize(numThreads);
			dataSent += chls[i][0]->getTotalDataSent();
			dataRecv += chls[i][0]->getTotalDataRecv();
		}
	}

	std::cout << IoStream::lock;
	std::cout << "party #" << myIdx << "\t Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << IoStream::unlock;


	//close chanels 
	for (u64 i = 0; i < nParties; ++i)
		if (i != myIdx)
			for (u64 j = 0; j < numChannelThreads; ++j)
				chls[i][j]->close();

	for (u64 i = 0; i < nParties; ++i)
		if (i != myIdx)
			ep[i].stop();

	ios.stop();

	
}



inline void OKVS_poly(u64 setSize) {
	
	PRNG prng(_mm_set_epi32(4253465, 3434565, 0, 0));
	
	std::vector<block> input (setSize);
	for (int i = 0; i < input.size(); i++) {
		input[i] = prng.get<block>();
		std::cout << input[i] << std::endl;
		std::cout << hex;
	}

	std::cout << "============================================================" << std::endl;

	std::vector<block> value(setSize);
	for (int i = 0; i < value.size(); i++) {
		value[i] = prng.get<block>();
		std::cout << value[i] << std::endl;
		std::cout << hex;
	}

	//Encode OKVS table 
	std::vector<block> coefficients(setSize);
	PolyEncode(input, value, coefficients);

	std::vector<block> input2(1);
	input2[0] = input[1];

	std::vector<block> decoded2(1);

	//Decode OKVS for receiver's input
	std::vector<block> decoded_value(setSize);
	PolyDecode(coefficients, input, decoded_value);
	for (int i = 0; i < decoded_value.size(); i++) {
		std::cout << decoded_value[i] << std::endl;
		std::cout << hex;
	}



}
