package bip25519

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/ecadlabs/hdw"
	"github.com/ecadlabs/hdw/bip25519/ex25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustHex(src string) []byte {
	data, err := hex.DecodeString(src)
	if err != nil {
		panic(err)
	}
	return data
}

func mustDerive(src hdw.PrivateKey, index uint32) hdw.PrivateKey {
	k, err := src.Derive(index)
	if err != nil {
		panic(err)
	}
	return k
}

type testKeyData struct {
	path    []uint32
	chain   string
	private string
	public  string
}

type testChain struct {
	mnemonic string
	seed     string
	opt      Options
	keys     []testKeyData
}

var edTestDataHMAC = []testChain{
	{
		seed: "000102030405060708090a0b0c0d0e0f",
		opt:  Options{HMAC: true, Mode: ModeRetry},
		keys: []testKeyData{
			{
				path:    []uint32{},
				chain:   "4b11419b53d0c31c6a2048b1e92c3152f7bc1dce6469cf88787e92bc7ddd4a23",
				private: "587049cb3630fb0f04b98d9e8b24a10a75e2b028d556c13877cecb6ab12e725f831a58390f707d4f623b7e2916239bfd821758e53d3e81aeac9e967714064c55",
			},
			{
				path:    []uint32{0 | hdw.Hard},
				chain:   "bbd2e77e76697e7a062742e8d1018b4981680e1b06a46d110c91719cde1babff",
				private: "f8c5fe7ef12d7a7f787aa7c3ba107b07f15b9de49528b681f3229f5cb62e725fb74792aee99adb5aeb18e6496d3c8b4d4f84186aacd65d5bd4067c7b39a80fce",
			},
			{
				path:    []uint32{0 | hdw.Hard, 1},
				chain:   "1911b561b3cc8e1b48ed9e447e3376bbc1ce3623be19580dbffa54ae7070a601",
				private: "b08950f1e6198ae164f7a2bb458890565887b09fb3fc25bb1cfd1340bb2e725f2a5f64e1bbc9c3d13a35649178cd23d04b700e3aae9fb2f2c119b1b7e01790d8",
			},
			{
				path:    []uint32{0 | hdw.Hard, 1, 2 | hdw.Hard},
				chain:   "754a9eb5e7a29d6859c404edbf590dee4ea8a9c8fdda160ff912f047f0a1269e",
				private: "58d6ce2c3a72ecfaa74a3ef356ecc3e31d72c65386f136e0126361d7c02e725f924802834f14c7484ab476d00bf194fd9cb42ad8a55b0c903bcf8521784945a6",
			},
			{
				path:    []uint32{0 | hdw.Hard, 1, 2 | hdw.Hard, 2},
				chain:   "7fa351f22ff6b1d7a2f7d5bcaff17be5b9d9f7a38770425b87dd7e1725e42133",
				private: "d8a6948b9aeb8b1d18b4ed1d8a432cf76abf3fd42f98cd8231c9663ac22e725f1daf4570d537cbf155b57e323005eec8651c8a6204133f84200f54dfefb64910",
			},
			{
				path:    []uint32{0 | hdw.Hard, 1, 2 | hdw.Hard, 2, 1000000000},
				chain:   "c17727ab677b6d8060485e7d1fdf96ac5b9ef287fb91beacf6db019dcada5af3",
				private: "70e17ad2d629acb9500cdb899fce121e74402e73ab8afc8947865b98c22e725fcfb410fa2dabd9b1ee9975fb0964e16a0371ad4f35c285b830ffd214dcf050fd",
			},
		},
	},
	{
		seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
		opt:  Options{HMAC: true, Mode: ModeRetry},
		keys: []testKeyData{
			{
				path:    []uint32{},
				chain:   "78fe3dbc48c922324d02156f4d0b6508ede14c9bb62a5b542223ac8fa5745953",
				private: "101cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4052ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
			},
			{
				path:    []uint32{0},
				chain:   "0c583578e39679489d895162d015375913db9cccf585c946b5d663b381497176",
				private: "c0118293fc269db1b5df4b5904deb8ef6eb2c0cd184c198a4317464224ab40528db4861a969864cc3915e901b2103c5c15d45176504e27c945fdbccada2d2c39",
			},
			{
				path:    []uint32{0, 2147483647 | hdw.Hard},
				chain:   "07cc242e4340750b183ba703d73b3ca49aa6ef035932fd661e23edf541c5e65c",
				private: "d89c292cb8073ff8e7027c49b69ae66b3e8e85d4d0f50e67f64080c928ab4052727b02c5ba8c12cdbd95f107cdd9be572cfa9a3adb3e35adf3af739b969b932d",
			},
			{
				path:    []uint32{0, 2147483647 | hdw.Hard, 1},
				chain:   "00ad9b5fab68c99ad553726fae8f1889037988c288bf43f1952d844f4313c141",
				private: "a82fc48a79e1c13345eb17c48addd040be20641b65486cb9870b63a82fab4052d366fe78a4204dfe4dfc4f16d15c55aafb2eb6675438c56aa77884176c85d6b8",
			},
			{
				path:    []uint32{0, 2147483647 | hdw.Hard, 1, 2147483646 | hdw.Hard},
				chain:   "d07fd3e133f9a8326d97ad07f979628894a887eaba33b7fb23aaabbe081c9b73",
				private: "b869ff3dc100cfb37f18658ca7bcb71e778e0422a37f912a8df0409533ab40524f8b2ed57b1e9004e64e0e08921495952cf4654b164c70d42e36bb4d6d935fca",
			},
			{
				path:    []uint32{0, 2147483647 | hdw.Hard, 1, 2147483646 | hdw.Hard, 2},
				chain:   "a83b350fd471da44a3e113c203a3abe62702595de8fb3a73b293dcb0c7716ebc",
				private: "780e9e94417b363be7bd19d7c69fc011482089e5b67293a8313248cc39ab4052e343dd5764a5f5fe9be81e262e7888d783bdc72bc88054e897dca2231cfe1ce3",
			},
		},
	},
	// from BOLOS
	{
		seed: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
		opt:  Options{HMAC: true, Mode: ModeRetry},
		keys: []testKeyData{
			{
				path:    []uint32{4294967295 | hdw.Hard},
				chain:   "f5977507899c96ab6d5f63ae730a0f2235cb98b3bced3549a10e19bd1297012d",
				private: "9855268c84d2eca6266238063eee03ac5d1a44c83eb9341924d5559b19e69d41d6f0b87c340f994230fac06e6bf5b87a0f3f584f9bf157f9845c7545e8d8eb78",
			},
			{
				path:    []uint32{44 | hdw.Hard, 148 | hdw.Hard, 0, 0},
				chain:   "3e7bea48e16cef3f4e67460e0297557f2df425d52aff8fca1c1ad2b976c57afb",
				private: "e0176952fb330646b3126ee91aa73bf44b4bf18f17ce4ac3a74a53d120e69d413ca5c28877f73b21fb01ebe7799233f40bde61a058fb9a9facfc10ac695c0fc9",
			},
			{
				path:    []uint32{44 | hdw.Hard, 148, 1, 2},
				chain:   "40418c80e21c94bddfcab2318f9a82fb65739c687e09fee15c172778b04cc1af",
				private: "207c589bf02f2cbfadaf8024e1dd27a5b77f01571ddb40c4ee78d7d329e69d41a6045bdebc8c836298881804ff424ee187c4141f49f8fda253f8ac3df2cda6bf",
			},
		},
	},
	// from Ledger
	/*
		{
			mnemonic: "miracle blush border auto country easily icon below finish fruit base shift lift old farm wild room symbol ocean attitude ill tank soon know",
			opt:      Options{HMAC: true, Mode: ModeRetry},
			keys: []testKeyData{
				{
					path:   []uint32{44 | hdw.BIP32Hard, 1729 | hdw.BIP32Hard},
					public: "1e254bee6b491847c3e0c55050528f15ea6a2c12d92197184a6c0b5b81b16822", // edpktsVy6rwX81gm8TdffF5a5dTzu21wgDna9tqaxueQWapy9C5rcj
				},
			},
		},
	*/
	// ocaml-bip32-ed25519
	{
		seed: "cd072cd8be6f9f62ac4c09c28206e7e35594aa6b342f5d0a3a5e4842fab428f7",
	},
	{
		seed: "b2c8e0121c441ae614a7b8d92a9219af1ece87545758de781ef34f8ff48dc719",
	},
	{
		seed: "7a89f3baca974053ebea21b4e833d7deccbc1f10ccc5e9304fc1c1ea4f624891",
		keys: []testKeyData{
			{
				path:    []uint32{2147483616, 391769539, 2147483613 | hdw.Hard},
				private: "9862894d0eb22bbb4741674fba164dcc813819550033b3a02aceed37bb45b64477b8f2591096a3c78146fbbc25b4c62b0bd7e69a62580b627abba99ae804f580",
				chain:   "3b6446ab43882f485b9053b17fac6a0630c9539b8b7e0355d1a1f29e1c8c8f0c",
				public:  "ca55409840df909166c015ef5852664bd6e73868735a40b70666ecbe9167bec4",
			},
		},
	},
	{
		seed: "8e117bff8b32ceee02e6417d1137eb1beb9d2b4db7d91f8d03eb844a7d35e1b4",
		keys: []testKeyData{
			{
				path:    []uint32{2147483617 | hdw.Hard},
				private: "089bb79cbb0d9f56ce27fdde9e55794e18873fcaa3cf252c3c198136561078439f3bb715d1cb8252c0985164a4eef1de87fcb86ee0b22ec984569d09d40dd13c",
				chain:   "383b263ce77c12f17ab002f16daf8c61fd61b1820afbd85b653ebf8ca4a66737",
				public:  "f1734e2a5eb8736c4fcc408803ac6190415b5131c2cd38886b1104025e8e674d",
			},
		},
	},
	{
		seed: "5c090534721fbef64741a7cc925f6a9aa745178c77126e960ee8a34905cdea71",
		keys: []testKeyData{
			{
				path:    []uint32{1039842312},
				private: "7074fced69f08a2d6d4217c5e8e2bf636deb7376e4b9abb92cc7e1b4fcafe549b199e906366ad6d86fb4345f7f9efcb8eadef994a06a300a30c0f2f62f33e95b",
				chain:   "33da2582da03de4efe119bfeae611b3b3f5625d05998c8239aa5026471bd6d24",
				public:  "988df8e215f34ba49cfc7309f6473e863662ee0057973308e53b27890677e539",
			},
		},
	},
}

func TestBIP25519(t *testing.T) {
	for _, chain := range edTestDataHMAC {
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
			root := newKeyFromSeed(s, &chain.opt)
			if chain.keys == nil {
				require.Nil(t, root)
			}
			for _, k := range chain.keys {
				result, err := root.DerivePath(k.path)
				require.NoError(t, err)
				if k.chain != "" {
					assert.Equal(t, mustHex(k.chain), result.(*PrivateKey).ChainCode)
				}
				if k.private != "" {
					assert.Equal(t, ex25519.PrivateKey(mustHex(k.private)), result.(*PrivateKey).PrivateKey[:64])
				}
				if k.public != "" {
					assert.Equal(t, ed25519.PublicKey(mustHex(k.public)), result.(*PrivateKey).Public().(ed25519.PublicKey))
				}
			}
		})
	}
}

func TestBIP25519Derive(t *testing.T) {
	root, err := keyFromBytes(mustHex("80660d61ec16a6ca93e05e1738082dff22a422f00e95a5dfa9d91a74fab4725a017255017df26d8ff29dbe315c838cd3837a311e611a9dd1c8c8a82a21ad2ec314828443112319ee3ee64c82cda51c0f0df3c9550994bf70b4383d234e6e8ffd"))
	require.NoError(t, err)

	key1, _ := mustDerive(root, 1).(*PrivateKey)
	assert.Equal(t, mustHex("c02210e035578f15b48ad54d90d59a88352d3160f36d0458b3e1583302b5725a435748df6415038a8fe35c46779fea8554b747a9093a8f784cf079144fc00317594479b4ed8519d7c4378a9d7c782029f61d4ec107900b8dfb70c7d609ad5a16"), key1.bytes())

	key1 = mustDerive(root, 0|hdw.Hard).(*PrivateKey)
	assert.Equal(t, mustHex("20eeb6d38c858686b848a2f380d52d04ed1d87dba5f01f5cabe6b86e00b5725aa9f78d23bc28ed03d356d31c3842eec69609e6b207b438e0e804ab00316eec5f1af28001980d11f2b6247ad874b217f4fd50f6b785223b658fb079ce5cdd82b2"), key1.bytes())
}

func TestBIP25519DeriveParallel(t *testing.T) {
	mnemonic := "nel mezzo del cammin di nostra vita mi ritrovai per una selva oscura"
	seed := hdw.NewSeedFromMnemonic(mnemonic, "")
	path := hdw.Path{0, 1, 2, 1000}
	root := NewKeyFromSeed(seed, &Options{Mode: ModeRetry})

	// derive private
	key1, err := root.DerivePath(path)
	require.NoError(t, err)

	// derive public
	key2, err := root.ExtendedPublic().DerivePath(path)
	require.NoError(t, err)

	assert.True(t, key2.Equal(key1.Public()))
}
