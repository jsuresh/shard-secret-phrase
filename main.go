package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/shamir"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
)

var rootCmd = &cobra.Command{
	Use:   "shard-secret-phrase",
	Short: "A CLI to shard a secret using shamir secret sharing, generating BEB39 encoded human readable shards",
	Long: `
Best practice seed phrase backup using shamir secret sharing to create overlapping human redable shards
`,
}

var split = &cobra.Command{
	Use:   "split N M",
	Short: "Split secret phrase using a N/M scheme s.t the original can be re-created with any N shards out of M",
	Long: `
Secret phrase is first decoded from BIP39 into it's original entropy, which is then split using shamir secret sharing,
where each shard is then chunked into 20 byte chunks and re-encoded using BIP39. The last byte in each 20 byte chunk is
the chunk length.
`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		threshold, err := strconv.Atoi(args[0])
		if err != nil {
			log.Fatalf("Could not parse first argument (minShards, N): %v", err)
		}

		numShares, err := strconv.Atoi(args[1])
		if err != nil {
			log.Fatalf("Could not parse second argument (totalShards, M): %v", err)
		}

		if threshold > numShares {
			log.Fatalf("First argument must be less than second argument (N < M): %v", err)
		}

		// read and parse encryption shards, to re-create the encryption key
		mnemonic, err := io.ReadAll(os.Stdin)

		if err != nil {
			log.Fatalf("Error reading seed phrase from stdin: %v", err)
		}

		entropy, err := bip39.EntropyFromMnemonic(string(mnemonic))

		shards, err := shamir.Split(entropy, numShares, threshold)
		if err != nil {
			log.Fatalf("Error splitting seed phrase into %d/%d shares using SSS: %v", threshold, numShares, err)
		}

		for _, shard := range shards {
			// encoded each shard using BIP39, where each chunk is 20 bytes, with the last byte in the
			// chunk the chunk size
			var shardMnemonicChunks []string
			for j := 0; j < len(shard); j += 19 {
				var chunk []byte
				if j+19 > len(shard) {
					chunk = shard[j:]
				} else {
					chunk = shard[j : j+19]
				}
				padding := make([]byte, 19-len(chunk))
				padding = append(padding, byte(len(chunk)))
				chunk = append(chunk, padding...)
				chunkBIP39, err := bip39.NewMnemonic(chunk)
				if err != nil {
					panic(err)
				}
				shardMnemonicChunks = append(shardMnemonicChunks, chunkBIP39)
			}

			fmt.Printf("%s\n", strings.Join(shardMnemonicChunks, " "))
		}
	},
}

var assemble = &cobra.Command{
	Use:   "assemble",
	Short: "Re-assemble a pass phrase from a set of shards, one per line, read from stdin",
	Long: `
Re-assemble a pass phrase from a set of shards. For usability, each shard is BIP39 encoded into 20 byte chunks.
For example, what was originally a 12 word secret phrase, will be split into 15 word shards.

A 24 seed phrase gets split into 30 word shards, where each shards is composed of 2 BIP39 encoded chunks (that is
in this example, one shard is compromised of two BIP39 encoded 15 word shards)
`,
	Run: func(cmd *cobra.Command, args []string) {
		// read and parse encryption shards, to re-create the encryption key
		allShardMnemonics, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("Error reading key shards: %v", err)
		}

		var providedShards [][]byte
		for i, mnemonic := range strings.Split(string(allShardMnemonics), "\n") {
			if len(mnemonic) == 0 {
				break
			}
			mnemonicWords := strings.Split(mnemonic, " ")

			var shard []byte
			for j := 0; j < len(mnemonicWords); j += 15 {
				chunkMnemonic := strings.Join(mnemonicWords[j:j+15], " ")
				chunk, err := bip39.EntropyFromMnemonic(chunkMnemonic)
				if err != nil {
					log.Fatalf("Error parsing chunk %d/%d from shard: %v", j, i, err)
				}

				shard = append(shard, chunk[0:int(chunk[len(chunk)-1])]...)
			}

			providedShards = append(providedShards, shard)
		}

		recoveredEntropy, err := shamir.Combine(providedShards)
		if err != nil {
			log.Fatalf("Error recovering secret from shards: %v", err)
		}

		recoveredMnemonic, err := bip39.NewMnemonic(recoveredEntropy)
		if err != nil {
			log.Fatalf("Error converting entropy: %x into mnemonic: %v", recoveredEntropy, err)
		}

		fmt.Printf("%s\n", string(recoveredMnemonic))
	},
}

func main() {
	rootCmd.AddCommand(split)
	rootCmd.AddCommand(assemble)
	rootCmd.Execute()
}
