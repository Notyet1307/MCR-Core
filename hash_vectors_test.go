package mcr_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	mcr "github.com/Notyet1307/MCR-Core"
)

func TestIndependentLegacyHashVectors(t *testing.T) {
	var vectors []struct {
		EventID      string `json:"event_id"`
		PreviousHash string `json:"previous_hash"`
		HashCore     struct {
			EventID   string          `json:"event_id"`
			EventType string          `json:"event_type"`
			Timestamp string          `json:"timestamp"`
			Actor     mcr.Actor       `json:"actor"`
			Payload   json.RawMessage `json:"payload"`
		} `json:"hash_core"`
		ExpectedDigest string `json:"expected_digest"`
	}
	readHashVectors(t, "testdata/hashes/legacy-events.json", &vectors)
	if len(vectors) == 0 {
		t.Fatal("legacy vectors are empty")
	}
	for _, vector := range vectors {
		t.Run(vector.EventID, func(t *testing.T) {
			core, err := json.Marshal(vector.HashCore)
			if err != nil {
				t.Fatal(err)
			}
			input := append(append(append([]byte(nil), core...), '\n'), vector.PreviousHash...)
			digest := sha256.Sum256(input)
			actual := "sha256:" + hex.EncodeToString(digest[:])
			if actual != vector.ExpectedDigest {
				t.Fatalf("digest = %q, want %q", actual, vector.ExpectedDigest)
			}
		})
	}
}

func TestIndependentNativeHashVectors(t *testing.T) {
	var vectors []struct {
		Name           string          `json:"name"`
		HashCore       json.RawMessage `json:"hash_core"`
		ExpectedDigest string          `json:"expected_digest"`
	}
	readHashVectors(t, "testdata/hashes/native-records.json", &vectors)
	if len(vectors) == 0 {
		t.Fatal("native vectors are empty")
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			digest := sha256.Sum256(vector.HashCore)
			actual := "sha256:" + hex.EncodeToString(digest[:])
			if actual != vector.ExpectedDigest {
				t.Fatalf("digest = %q, want %q", actual, vector.ExpectedDigest)
			}
		})
	}
}

func readHashVectors(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}
