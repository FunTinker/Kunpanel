package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	passwordHashPrefix = "$argon2id$"
	argonTime          = 3
	argonMemory        = 64 * 1024
	argonThreads       = 2
	argonKeyLength     = 32
)

var passwordHashSlots = make(chan struct{}, 2)

func hashPassword(password string, salt []byte) string {
	passwordHashSlots <- struct{}{}
	defer func() { <-passwordHashSlots }()
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash))
}

func legacyHashPassword(password string, salt []byte) string {
	value := append(append([]byte(nil), salt...), []byte(password)...)
	sum := sha256.Sum256(value)
	for i := 0; i < 600000; i++ {
		h := sha256.New()
		_, _ = h.Write(sum[:])
		_, _ = h.Write(salt)
		sum = sha256.Sum256(h.Sum(nil))
	}
	return hex.EncodeToString(sum[:])
}

func verifyPassword(password, encoded, legacySalt string) (valid, needsRehash bool) {
	if !strings.HasPrefix(encoded, passwordHashPrefix) {
		salt, err := base64.RawStdEncoding.DecodeString(legacySalt)
		if err != nil {
			return false, false
		}
		expected, err := hex.DecodeString(encoded)
		if err != nil {
			return false, false
		}
		actual, err := hex.DecodeString(legacyHashPassword(password, salt))
		return err == nil && subtle.ConstantTimeCompare(expected, actual) == 1, true
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return false, false
	}
	var memory uint32
	var iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil || memory == 0 || iterations == 0 || threads == 0 {
		return false, false
	}
	// Refuse attacker-controlled parameters large enough to exhaust the server.
	if memory > 256*1024 || iterations > 10 || threads > 16 {
		return false, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 16 {
		return false, false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 64 {
		return false, false
	}
	passwordHashSlots <- struct{}{}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(expected)))
	<-passwordHashSlots
	valid = subtle.ConstantTimeCompare(expected, actual) == 1
	needsRehash = memory != argonMemory || iterations != argonTime || threads != argonThreads || len(expected) != argonKeyLength
	return valid, needsRehash
}
