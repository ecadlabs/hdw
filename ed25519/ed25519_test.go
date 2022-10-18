package ed25519

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/ecadlabs/hdw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testKeyData struct {
	path    []uint32
	chain   string
	private string
	public  string
}

type testChain struct {
	mnemonic string
	seed     string
	keys     []testKeyData
}

var edTestData = []testChain{
	{
		seed: "000102030405060708090a0b0c0d0e0f",
		keys: []testKeyData{
			{
				path:    []uint32{},
				chain:   "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
				private: "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
				public:  "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
			},
			{
				path:    []uint32{0 | hdw.Hard},
				chain:   "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
				private: "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
				public:  "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
			},
			{
				path:    []uint32{0 | hdw.Hard, 1 | hdw.Hard},
				chain:   "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
				private: "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
				public:  "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
			},
			{
				path:    []uint32{0 | hdw.Hard, 1 | hdw.Hard, 2 | hdw.Hard},
				chain:   "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
				private: "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
				public:  "ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
			},
			{
				path:    []uint32{0 | hdw.Hard, 1 | hdw.Hard, 2 | hdw.Hard, 2 | hdw.Hard},
				chain:   "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
				private: "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
				public:  "8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
			},
			{
				path:    []uint32{0 | hdw.Hard, 1 | hdw.Hard, 2 | hdw.Hard, 2 | hdw.Hard, 1000000000 | hdw.Hard},
				chain:   "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
				private: "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
				public:  "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
			},
		},
	},
	{
		seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
		keys: []testKeyData{
			{
				path:    []uint32{},
				chain:   "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
				private: "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
				public:  "8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a",
			},
			{
				path:    []uint32{0 | hdw.Hard},
				chain:   "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
				private: "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
				public:  "86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037",
			},
			{
				path:    []uint32{0 | hdw.Hard, 2147483647 | hdw.Hard},
				chain:   "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
				private: "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
				public:  "5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d",
			},
			{
				path:    []uint32{0 | hdw.Hard, 2147483647 | hdw.Hard, 1 | hdw.Hard},
				chain:   "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
				private: "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
				public:  "2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45",
			},
			{
				path:    []uint32{0 | hdw.Hard, 2147483647 | hdw.Hard, 1 | hdw.Hard, 2147483646 | hdw.Hard},
				chain:   "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
				private: "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
				public:  "e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
			},
			{
				path:    []uint32{0 | hdw.Hard, 2147483647 | hdw.Hard, 1 | hdw.Hard, 2147483646 | hdw.Hard, 2 | hdw.Hard},
				chain:   "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
				private: "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
				public:  "47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
			},
		},
	},
	// from Ledger
	{
		mnemonic: "miracle blush border auto country easily icon below finish fruit base shift lift old farm wild room symbol ocean attitude ill tank soon know",
		keys: []testKeyData{
			{
				path:   []uint32{44 | hdw.Hard, 1729 | hdw.Hard},
				public: "38739082097b0c14cb2cd92b800476e5d2310e30f921da58fc30d423a10de8a4",
			},
		},
	},
	// BOLOS
	{
		seed: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
		keys: []testKeyData{
			{
				path:    []uint32{738197632 | hdw.Hard, 335544448 | hdw.Hard, 0 | hdw.Hard, 0 | hdw.Hard},
				chain:   "b609a7af6a8ae5568bff26a3747aa0c4d8b383144db5c3da28650a37015f2503",
				private: "9761691a62523b637c55aa267b3c4835b7cdd4bb704b399a0f7290ca570262cb",
			},
			{
				path:    []uint32{738197504 | hdw.Hard, 335544320 | hdw.Hard, 16777216 | hdw.Hard, 33554432 | hdw.Hard},
				chain:   "1a8e8df02b17fd4632529dab6443887359ecf94d547291535952b412cba88420",
				private: "e36a66d67ea0d2dcf9af54bc4617c0fa0724b42acff17501ac9dd27588bbd7dd",
			},
			{
				path:    []uint32{44 | hdw.Hard, 148 | hdw.Hard, 0 | hdw.Hard, 0 | hdw.Hard},
				chain:   "ad38cb3640dd5a1e7540030761ec7ade17a8b38a203c37072647ec22eea7a3ba",
				private: "a044cf4dcc4c6206d64ea3a7dae79337afcd61808dc6239a22c1ba1f4618c055",
			},
			{
				path:    []uint32{44 | hdw.Hard, 148 | hdw.Hard, 1 | hdw.Hard, 2 | hdw.Hard},
				chain:   "fbc472b0a324f71f264c6b002524a93a690a3d9fd130c9ca949d0ccc1e37b07e",
				private: "889fc3bc31029c0f09eb6a24f1617af15b919dc9a6b3caac3c57383da094a157",
			},
		},
	},
}

func mustHex(src string) []byte {
	data, err := hex.DecodeString(src)
	if err != nil {
		panic(err)
	}
	return data
}

func TestED25519(t *testing.T) {
	for _, chain := range edTestData {
		name := chain.seed
		if name == "" {
			name = "mnemonic"
		}
		t.Run(name, func(t *testing.T) {
			var s []byte
			if chain.mnemonic != "" {
				s = hdw.NewSeedFromMnemonic(chain.mnemonic, "")
			} else {
				s = mustHex(chain.seed)
			}
			root := NewKeyFromSeed(s)

			for _, k := range chain.keys {
				result, err := root.DerivePath(k.path)
				require.NoError(t, err)
				if k.chain != "" {
					assert.Equal(t, mustHex(k.chain), result.(*PrivateKey).ChainCode)
				}
				if k.private != "" {
					assert.Equal(t, mustHex(k.private), result.(*PrivateKey).Seed())
				}
				if k.public != "" {
					assert.Equal(t, ed25519.PublicKey(mustHex(k.public)), result.(*PrivateKey).Public().(ed25519.PublicKey))
				}
			}
		})
	}
}
