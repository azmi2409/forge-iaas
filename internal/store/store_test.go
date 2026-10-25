package store

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

var testKeyBytes = bytes.Repeat([]byte("k"), 32)

func TestMasterKeyFromEnvUnsetIsEphemeral(t *testing.T) {
	t.Setenv("FIAAS_MASTER_KEY", "")
	key, ephemeral, err := MasterKeyFromEnv()
	if err != nil {
		t.Fatalf("MasterKeyFromEnv: %v", err)
	}
	if !ephemeral {
		t.Fatal("expected ephemeral=true when unset")
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}
}

func TestMasterKeyFromEnvBase64(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString(testKeyBytes)
	t.Setenv("FIAAS_MASTER_KEY", enc)
	key, ephemeral, err := MasterKeyFromEnv()
	if err != nil {
		t.Fatalf("MasterKeyFromEnv: %v", err)
	}
	if ephemeral {
		t.Fatal("expected ephemeral=false for a set key")
	}
	if !bytes.Equal(key, testKeyBytes) {
		t.Fatal("base64 key mismatch")
	}
}

func TestMasterKeyFromEnvRaw32(t *testing.T) {
	raw := strings.Repeat("r", 32)
	t.Setenv("FIAAS_MASTER_KEY", raw)
	key, _, err := MasterKeyFromEnv()
	if err != nil {
		t.Fatalf("MasterKeyFromEnv: %v", err)
	}
	if string(key) != raw {
		t.Fatal("raw key mismatch")
	}
}

func TestMasterKeyFromEnvInvalid(t *testing.T) {
	t.Setenv("FIAAS_MASTER_KEY", "too-short")
	if _, _, err := MasterKeyFromEnv(); err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	ct, err := Encrypt(testKeyBytes, []byte("hello state"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(ct, []byte("hello state")) {
		t.Fatal("ciphertext contains plaintext")
	}
	pt, err := Decrypt(testKeyBytes, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != "hello state" {
		t.Fatalf("round-trip mismatch: %q", pt)
	}
	// Wrong key and tampering must fail.
	wrong := bytes.Repeat([]byte("x"), 32)
	if _, err := Decrypt(wrong, ct); err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}
	tampered := append([]byte{}, ct...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := Decrypt(testKeyBytes, tampered); err == nil {
		t.Fatal("expected decryption failure for tampered ciphertext")
	}
	if _, err := Decrypt(testKeyBytes, []byte("short")); err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}
