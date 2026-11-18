// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // PBO trailer validation requires SHA-1.
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const canonicalCorpusDir = "testdata"

var sha1DigestInfoPrefix = []byte{
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
}

type canonicalCorpusManifest struct {
	SourceManifest struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"source_manifest"`
	PublicKeys []canonicalCorpusFile        `json:"public_keys"`
	PBOOutputs []canonicalPBOArtifact       `json:"pbo_outputs"`
	Signatures []canonicalSignatureArtifact `json:"signatures"`
}

type canonicalCorpusFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type canonicalPBOArtifact struct {
	ID              string              `json:"id"`
	Path            string              `json:"path"`
	PayloadManifest canonicalCorpusFile `json:"payload_manifest,omitzero"`
	Properties      map[string]string   `json:"properties"`
	Bytes           int64               `json:"bytes"`
	SHA256          string              `json:"sha256"`
	EntryCount      int                 `json:"entry_count"`
	PayloadStart    int64               `json:"payload_start"`
	PayloadBytes    int64               `json:"payload_bytes"`
	PayloadEnd      int64               `json:"payload_end"`
	TrailerMarker   byte                `json:"trailer_marker"`
	TrailerSHA1     string              `json:"trailer_sha1"`
	IndependentSHA1 string              `json:"independent_sha1"`
}

type canonicalSignatureArtifact struct {
	ID             string `json:"id"`
	Path           string `json:"path"`
	Bytes          int64  `json:"bytes"`
	SHA256         string `json:"sha256"`
	InputPBO       string `json:"input_pbo"`
	InputPBOSHA256 string `json:"input_pbo_sha256"`
	GameType       string `json:"game_type"`
	Version        uint32 `json:"version"`
	Hashes         struct {
		Hash1 string `json:"hash1"`
		Hash2 string `json:"hash2"`
		Hash3 string `json:"hash3"`
	} `json:"hashes"`
}

type canonicalSourceManifest struct {
	FileCount  int                   `json:"file_count"`
	TreeSHA256 string                `json:"tree_sha256"`
	Files      []canonicalSourceFile `json:"files"`
}

// canonicalSourceFile describes one immutable source fixture.
type canonicalSourceFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// canonicalPayloadManifest pins decoded records from one original-tool PBO.
type canonicalPayloadManifest struct {
	SchemaVersion   int                   `json:"schema_version"`
	Provenance      string                `json:"provenance"`
	SourcePBOSHA256 string                `json:"source_pbo_sha256"`
	FileCount       int                   `json:"file_count"`
	TreeSHA256      string                `json:"tree_sha256"`
	Files           []canonicalSourceFile `json:"files"`
}

type biPublicKey struct {
	Name      string
	Modulus   *big.Int
	Exponent  uint32
	ModulusLE []byte
}

// TestCanonicalCorpusIntegrity verifies frozen fixture bytes without using PBO or bisign APIs.
func TestCanonicalCorpusIntegrity(t *testing.T) {
	root := canonicalCorpusDir
	manifest := loadCanonicalCorpusManifest(t)

	sourceManifest := loadCanonicalSourceManifest(t, manifest)

	for _, source := range sourceManifest.Files {
		path := filepath.Join(root, "source", filepath.FromSlash(source.Path))
		data := readCorpusFile(t, path)
		if int64(len(data)) != source.Bytes {
			t.Errorf("source %q size=%d, want %d", source.Path, len(data), source.Bytes)
		}

		assertSHA256(t, data, source.SHA256, "source "+source.Path)
	}
	if got := canonicalSourceTreeSHA256(sourceManifest.Files); got != sourceManifest.TreeSHA256 {
		t.Errorf("source tree SHA-256=%s, want %s", got, sourceManifest.TreeSHA256)
	}

	for _, key := range manifest.PublicKeys {
		data := readCorpusFile(t, filepath.Join(root, filepath.FromSlash(key.Path)))
		assertSHA256(t, data, key.SHA256, "public key "+key.Path)
	}

	for _, artifact := range manifest.PBOOutputs {
		data := readCorpusFile(t, filepath.Join(root, filepath.FromSlash(artifact.Path)))
		if int64(len(data)) != artifact.Bytes {
			t.Errorf("PBO %s size=%d, want %d", artifact.ID, len(data), artifact.Bytes)
		}

		assertSHA256(t, data, artifact.SHA256, "PBO "+artifact.ID)
		verifyCanonicalPBO(t, data, artifact)
		if artifact.PayloadManifest.Path != "" {
			_ = loadCanonicalPayloadManifest(t, artifact)
		}
	}

	for _, signature := range manifest.Signatures {
		sigData := readCorpusFile(t, filepath.Join(root, filepath.FromSlash(signature.Path)))
		if int64(len(sigData)) != signature.Bytes {
			t.Errorf("signature %s size=%d, want %d", signature.ID, len(sigData), signature.Bytes)
		}

		assertSHA256(t, sigData, signature.SHA256, "signature "+signature.ID)

		pboData := readCorpusFile(t, filepath.Join(root, filepath.FromSlash(signature.InputPBO)))
		assertSHA256(t, pboData, signature.InputPBOSHA256, "signature input PBO "+signature.ID)
		version, hashes, key, err := recoverCanonicalSignatureHashes(sigData)
		if err != nil {
			t.Errorf("recover %s hash vectors: %v", signature.ID, err)
			continue
		}

		if version != signature.Version {
			t.Errorf("signature %s version=%d, want %d", signature.ID, version, signature.Version)
		}

		assertDigest(t, hashes[0], signature.Hashes.Hash1, signature.ID+" hash1")
		assertDigest(t, hashes[1], signature.Hashes.Hash2, signature.ID+" hash2")
		assertDigest(t, hashes[2], signature.Hashes.Hash3, signature.ID+" hash3")

		keyName := "canonical-" + signature.GameType
		if key.Name != keyName {
			t.Errorf("signature %s embedded key=%q, want %q", signature.ID, key.Name, keyName)
		}

		publicPath := filepath.Join(root, "keys", keyName+".bikey")
		publicData := readCorpusFile(t, publicPath)
		publicKey, err := parseCanonicalPublicKey(publicData)
		if err != nil {
			t.Errorf("parse public key for %s: %v", signature.ID, err)
			continue
		}

		if publicKey.Name != key.Name ||
			publicKey.Exponent != key.Exponent ||
			!bytes.Equal(publicKey.ModulusLE, key.ModulusLE) {
			t.Errorf("signature %s embedded key does not match %s", signature.ID, publicPath)
		}
	}
}

// TestComputeHashSetMatchesOriginalSignatureVectors checks all canonical signer digests.
func TestComputeHashSetMatchesOriginalSignatureVectors(t *testing.T) {
	t.Parallel()

	manifest := loadCanonicalCorpusManifest(t)

	for _, signature := range manifest.Signatures {
		t.Run(signature.ID, func(t *testing.T) {
			t.Parallel()

			pboPath := filepath.Join(canonicalCorpusDir, filepath.FromSlash(signature.InputPBO))
			hashes, err := ComputeHashSet(
				pboPath,
				SignVersion(signature.Version),
				GameType(signature.GameType),
			)
			if err != nil {
				t.Fatalf("ComputeHashSet(%s): %v", signature.ID, err)
			}

			assertDigest(t, hashes.Hash1, signature.Hashes.Hash1, signature.ID+" hash1")
			assertDigest(t, hashes.Hash2, signature.Hashes.Hash2, signature.ID+" hash2")
			assertDigest(t, hashes.Hash3, signature.Hashes.Hash3, signature.ID+" hash3")
		})
	}
}

// loadCanonicalCorpusManifest reads the fixture index used by corpus tests.
func loadCanonicalCorpusManifest(t *testing.T) canonicalCorpusManifest {
	t.Helper()

	manifestData := readCorpusFile(t, filepath.Join(canonicalCorpusDir, "manifest.json"))
	var manifest canonicalCorpusManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("decode corpus manifest: %v", err)
	}

	return manifest
}

// loadCanonicalSourceManifest reads and verifies the self-authored source fixture index.
func loadCanonicalSourceManifest(t *testing.T, manifest canonicalCorpusManifest) canonicalSourceManifest {
	t.Helper()

	path := filepath.Join(canonicalCorpusDir, filepath.FromSlash(manifest.SourceManifest.Path))
	data := readCorpusFile(t, path)
	assertSHA256(t, data, manifest.SourceManifest.SHA256, "source manifest")
	var source canonicalSourceManifest
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatalf("decode source manifest: %v", err)
	}
	if len(source.Files) != source.FileCount {
		t.Fatalf("source file count=%d, manifest says %d", len(source.Files), source.FileCount)
	}

	return source
}

// loadCanonicalPayloadManifest verifies the expected extracted files against their source PBO.
func loadCanonicalPayloadManifest(t *testing.T, artifact canonicalPBOArtifact) canonicalPayloadManifest {
	t.Helper()

	path := filepath.Join(canonicalCorpusDir, filepath.FromSlash(artifact.PayloadManifest.Path))
	data := readCorpusFile(t, path)
	assertSHA256(t, data, artifact.PayloadManifest.SHA256, "payload manifest "+artifact.ID)
	var payload canonicalPayloadManifest
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode payload manifest %s: %v", artifact.ID, err)
	}

	if payload.SchemaVersion != 1 || payload.Provenance != "ORIGINAL_VERIFIED" {
		t.Fatalf("payload manifest %s has unsupported schema or provenance", artifact.ID)
	}
	if payload.SourcePBOSHA256 != artifact.SHA256 {
		t.Fatalf(
			"payload manifest %s is for PBO %s, want %s",
			artifact.ID, payload.SourcePBOSHA256, artifact.SHA256,
		)
	}
	if len(payload.Files) != payload.FileCount || payload.FileCount != artifact.EntryCount {
		t.Fatalf(
			"payload manifest %s file count=%d, want %d",
			artifact.ID, payload.FileCount, artifact.EntryCount,
		)
	}
	if got := canonicalSourceTreeSHA256(payload.Files); got != payload.TreeSHA256 {
		t.Fatalf(
			"payload manifest %s tree SHA-256=%s, want %s",
			artifact.ID, got, payload.TreeSHA256,
		)
	}

	return payload
}

// canonicalSourceTreeSHA256 returns the manifest tree digest for ordered path/size/hash rows.
func canonicalSourceTreeSHA256(files []canonicalSourceFile) string {
	rows := make([]string, 0, len(files))
	for _, file := range files {
		rows = append(rows, fmt.Sprintf("%s\x00%d\x00%s", file.Path, file.Bytes, strings.ToLower(file.SHA256)))
	}

	digest := sha256.Sum256([]byte(strings.Join(rows, "\n")))
	return hex.EncodeToString(digest[:])
}

// readCorpusFile reads one fixture and fails the test with its path on error.
func readCorpusFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus file %s: %v", path, err)
	}

	return data
}

// assertSHA256 compares fixture bytes with a lowercase hexadecimal SHA-256 value.
func assertSHA256(t *testing.T, data []byte, want, name string) {
	t.Helper()

	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != strings.ToLower(want) {
		t.Errorf("%s SHA-256=%s, want %s", name, got, want)
	}
}

// verifyCanonicalPBO independently parses the plain sequential PBO fixture and validates its trailer.
func verifyCanonicalPBO(t *testing.T, data []byte, artifact canonicalPBOArtifact) {
	t.Helper()

	if len(data) < 21 || data[0] != 0 || binary.LittleEndian.Uint32(data[1:5]) != uint32(MimeHeader) {
		t.Fatalf("PBO %s has an invalid Vers header", artifact.ID)
	}
	if !allZero(data[5:21]) {
		t.Fatalf("PBO %s has non-zero Vers header fields", artifact.ID)
	}

	offset := 21
	properties := make(map[string]string)
	for {
		key, next, err := readCanonicalCString(data, offset)
		if err != nil {
			t.Fatalf("PBO %s header key: %v", artifact.ID, err)
		}

		offset = next
		if key == "" {
			break
		}

		value, next, err := readCanonicalCString(data, offset)
		if err != nil {
			t.Fatalf("PBO %s property %q value: %v", artifact.ID, key, err)
		}

		if _, duplicate := properties[key]; duplicate {
			t.Fatalf("PBO %s has duplicate property %q", artifact.ID, key)
		}

		properties[key] = value
		offset = next
	}

	if !equalHeaderPropertyMap(properties, artifact.Properties) {
		t.Errorf("PBO %s properties=%v, want %v", artifact.ID, properties, artifact.Properties)
	}

	dataStart := int64(0)
	var payloadBytes int64
	entryCount := 0
	for {
		name, next, err := readCanonicalCString(data, offset)
		if err != nil {
			t.Fatalf("PBO %s entry name: %v", artifact.ID, err)
		}

		offset = next
		if len(data)-offset < 20 {
			t.Fatalf("PBO %s has a truncated entry record", artifact.ID)
		}

		fields := data[offset : offset+20]
		offset += 20
		if name == "" {
			if !allZero(fields) {
				t.Fatalf("PBO %s has a non-zero index terminator", artifact.ID)
			}

			dataStart = int64(offset)
			break
		}

		if binary.LittleEndian.Uint32(fields[8:12]) != 0 {
			t.Fatalf("PBO %s entry %q uses an unexpected explicit offset", artifact.ID, name)
		}

		payloadBytes += int64(binary.LittleEndian.Uint32(fields[16:20]))
		entryCount++
	}

	payloadEnd := dataStart + payloadBytes
	if entryCount != artifact.EntryCount ||
		payloadBytes != artifact.PayloadBytes ||
		dataStart != artifact.PayloadStart ||
		payloadEnd != artifact.PayloadEnd {
		t.Fatalf(
			"PBO %s extents entries=%d start=%d payload=%d end=%d; manifest says %d/%d/%d/%d",
			artifact.ID, entryCount, dataStart, payloadBytes, payloadEnd,
			artifact.EntryCount, artifact.PayloadStart, artifact.PayloadBytes, artifact.PayloadEnd,
		)
	}

	if payloadEnd < 0 || payloadEnd+21 != int64(len(data)) {
		t.Fatalf("PBO %s trailer extent=%d does not match file size %d", artifact.ID, payloadEnd, len(data))
	}

	marker := data[payloadEnd]
	if marker != artifact.TrailerMarker {
		t.Errorf("PBO %s trailer marker=%d, want %d", artifact.ID, marker, artifact.TrailerMarker)
	}

	computed := sha1.Sum(data[:payloadEnd]) //nolint:gosec // PBO trailer validation requires SHA-1.
	stored := data[payloadEnd+1 : payloadEnd+21]
	if got := hex.EncodeToString(stored); got != artifact.TrailerSHA1 {
		t.Errorf("PBO %s stored SHA-1=%s, want %s", artifact.ID, got, artifact.TrailerSHA1)
	}
	if got := hex.EncodeToString(computed[:]); got != artifact.IndependentSHA1 {
		t.Errorf("PBO %s computed SHA-1=%s, want independent=%s", artifact.ID, got, artifact.IndependentSHA1)
	}
	if !bytes.Equal(stored, computed[:]) {
		t.Errorf("PBO %s stored trailer does not match independent SHA-1", artifact.ID)
	}
}

// equalHeaderPropertyMap compares fixture header values without imposing an order absent from the manifest.
func equalHeaderPropertyMap(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}

	for key, value := range want {
		if got[key] != value {
			return false
		}
	}

	return true
}

// readCanonicalCString returns a NUL-terminated UTF-8 string and the next byte offset.
func readCanonicalCString(data []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(data) {
		return "", offset, errors.New("offset outside input")
	}

	end := bytes.IndexByte(data[offset:], 0)
	if end < 0 {
		return "", offset, errors.New("missing NUL terminator")
	}

	return string(data[offset : offset+end]), offset + end + 1, nil
}

// allZero reports whether every byte in b is zero.
func allZero(b []byte) bool {
	for _, value := range b {
		if value != 0 {
			return false
		}
	}

	return true
}

// recoverCanonicalSignatureHashes decodes all three RSA-SHA1 blocks from one original BI signature.
func recoverCanonicalSignatureHashes(data []byte) (uint32, [3][20]byte, biPublicKey, error) {
	var hashes [3][20]byte
	r := canonicalBinaryReader{data: data}
	key, blockSize, headerKey, headerExtra, tag, bits, exponent, err := r.readPublicKey()
	if err != nil {
		return 0, hashes, biPublicKey{}, err
	}
	if headerKey != 0x0206 || headerExtra != 0x2400 || tag != "RSA1" || bits%8 != 0 {
		return 0, hashes, biPublicKey{}, errors.New("invalid embedded BI public key header")
	}

	keyBytes := int(bits / 8)
	if int64(blockSize) != 20+int64(keyBytes) {
		return 0, hashes, biPublicKey{}, errors.New("embedded public key block size mismatch")
	}

	modulusLE, err := r.take(keyBytes)
	if err != nil {
		return 0, hashes, biPublicKey{}, err
	}

	key.ModulusLE = modulusLE
	key.Modulus = new(big.Int).SetBytes(reverseBytes(modulusLE))
	key.Exponent = exponent

	blocks := [3][]byte{}
	blocks[0], err = r.readSignatureBlock(keyBytes)
	if err != nil {
		return 0, hashes, biPublicKey{}, err
	}

	version, err := r.readUint32()
	if err != nil {
		return 0, hashes, biPublicKey{}, err
	}

	blocks[1], err = r.readSignatureBlock(keyBytes)
	if err != nil {
		return 0, hashes, biPublicKey{}, err
	}

	blocks[2], err = r.readSignatureBlock(keyBytes)
	if err != nil {
		return 0, hashes, biPublicKey{}, err
	}
	if r.offset != len(data) {
		return 0, hashes, biPublicKey{}, errors.New("trailing signature bytes")
	}

	for i, block := range blocks {
		hashes[i], err = recoverSHA1(block, key)
		if err != nil {
			return 0, hashes, biPublicKey{}, fmt.Errorf("block %d: %w", i+1, err)
		}
	}

	return version, hashes, key, nil
}

// parseCanonicalPublicKey reads one generated .bikey without using the bisign package.
func parseCanonicalPublicKey(data []byte) (biPublicKey, error) {
	var empty biPublicKey
	r := canonicalBinaryReader{data: data}
	key, blockSize, headerKey, headerExtra, tag, bits, exponent, err := r.readPublicKey()
	if err != nil {
		return empty, err
	}

	if headerKey != 0x0206 || headerExtra != 0x2400 || tag != "RSA1" || bits%8 != 0 {
		return empty, errors.New("invalid BI public key header")
	}

	keyBytes := int(bits / 8)
	if int64(blockSize) != 20+int64(keyBytes) {
		return empty, errors.New("public key block size mismatch")
	}

	modulusLE, err := r.take(keyBytes)
	if err != nil {
		return empty, err
	}
	if r.offset != len(data) {
		return empty, errors.New("trailing public key bytes")
	}

	key.ModulusLE = modulusLE
	key.Modulus = new(big.Int).SetBytes(reverseBytes(modulusLE))
	key.Exponent = exponent

	return key, nil
}

type canonicalBinaryReader struct {
	data   []byte
	offset int
}

// readPublicKey reads the BI public key header shared by .bikey and .bisign files.
func (r *canonicalBinaryReader) readPublicKey() (biPublicKey, uint32, uint32, uint32, string, uint32, uint32, error) {
	var key biPublicKey
	name, err := r.readCString()
	if err != nil {
		return key, 0, 0, 0, "", 0, 0, err
	}

	key.Name = name
	blockSize, err := r.readUint32()
	if err != nil {
		return key, 0, 0, 0, "", 0, 0, err
	}

	headerKey, err := r.readUint32()
	if err != nil {
		return key, 0, 0, 0, "", 0, 0, err
	}

	headerExtra, err := r.readUint32()
	if err != nil {
		return key, 0, 0, 0, "", 0, 0, err
	}

	tag, err := r.take(4)
	if err != nil {
		return key, 0, 0, 0, "", 0, 0, err
	}

	bits, err := r.readUint32()
	if err != nil {
		return key, 0, 0, 0, "", 0, 0, err
	}

	exponent, err := r.readUint32()
	if err != nil {
		return key, 0, 0, 0, "", 0, 0, err
	}

	return key, blockSize, headerKey, headerExtra, string(tag), bits, exponent, nil
}

// readSignatureBlock reads one fixed-width little-endian RSA signature block.
func (r *canonicalBinaryReader) readSignatureBlock(size int) ([]byte, error) {
	length, err := r.readUint32()
	if err != nil {
		return nil, err
	}

	if int(length) != size {
		return nil, fmt.Errorf("signature block size=%d, want %d", length, size)
	}

	return r.take(size)
}

// readCString reads one NUL-terminated UTF-8 string from the signature input.
func (r *canonicalBinaryReader) readCString() (string, error) {
	value, next, err := readCanonicalCString(r.data, r.offset)
	if err != nil {
		return "", err
	}

	r.offset = next
	return value, nil
}

// readUint32 reads one little-endian DWORD from the signature input.
func (r *canonicalBinaryReader) readUint32() (uint32, error) {
	data, err := r.take(4)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint32(data), nil
}

// take returns the next bounded byte range.
func (r *canonicalBinaryReader) take(size int) ([]byte, error) {
	if size < 0 || size > len(r.data)-r.offset {
		return nil, errors.New("truncated signature input")
	}

	out := r.data[r.offset : r.offset+size]
	r.offset += size

	return out, nil
}

// recoverSHA1 reverses the RSA public operation and validates PKCS#1 v1.5 SHA-1 padding.
func recoverSHA1(block []byte, key biPublicKey) ([20]byte, error) {
	var digest [20]byte
	if key.Modulus == nil || key.Exponent < 3 {
		return digest, errors.New("invalid RSA public key")
	}

	signature := new(big.Int).SetBytes(reverseBytes(block))
	if signature.Sign() <= 0 || signature.Cmp(key.Modulus) >= 0 {
		return digest, errors.New("RSA signature value out of range")
	}

	encodedInt := new(big.Int).Exp(signature, new(big.Int).SetUint64(uint64(key.Exponent)), key.Modulus)
	if len(encodedInt.Bytes()) > len(block) {
		return digest, errors.New("recovered RSA message is too large")
	}

	encoded := make([]byte, len(block))
	encodedInt.FillBytes(encoded)
	if len(encoded) < 2 || encoded[0] != 0 || encoded[1] != 1 {
		return digest, errors.New("invalid PKCS#1 block header")
	}

	separator := 2
	for separator < len(encoded) && encoded[separator] == 0xff {
		separator++
	}
	if separator-2 < 8 || separator >= len(encoded) || encoded[separator] != 0 {
		return digest, errors.New("invalid PKCS#1 padding")
	}

	separator++
	if len(encoded)-separator != len(sha1DigestInfoPrefix)+len(digest) ||
		!bytes.Equal(encoded[separator:separator+len(sha1DigestInfoPrefix)], sha1DigestInfoPrefix) {
		return digest, errors.New("invalid SHA-1 DigestInfo")
	}

	copy(digest[:], encoded[len(encoded)-len(digest):])
	return digest, nil
}

// reverseBytes returns a big-endian copy of BI's little-endian RSA integer.
func reverseBytes(input []byte) []byte {
	out := make([]byte, len(input))
	for i := range input {
		out[len(input)-1-i] = input[i]
	}

	return out
}

// assertDigest compares a recovered 20-byte digest with its manifest value.
func assertDigest(t *testing.T, got [20]byte, want, name string) {
	t.Helper()

	wantBytes, err := hex.DecodeString(want)
	if err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	if !bytes.Equal(got[:], wantBytes) {
		t.Errorf("%s=%x, want %s", name, got, want)
	}
}
