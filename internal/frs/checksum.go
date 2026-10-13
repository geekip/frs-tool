package frs

import (
	"encoding/binary"
	"math/bits"
)

const (
	xxhPrime1 uint64 = 11400714785074694791
	xxhPrime2 uint64 = 14029467366897019727
	xxhPrime3 uint64 = 1609587929392839161
	xxhPrime4 uint64 = 9650029242287828579
	xxhPrime5 uint64 = 2870177450012600261
)

// XXH64 返回 seed=0 的 XXH64，不是 XXH3。
func XXH64(data []byte) uint64 {
	return xxh64(data, false)
}

// FileChecksum 计算 FRS checksum，并把头部 48..55 字节视为零。
func FileChecksum(data []byte) uint64 {
	return xxh64(data, true)
}

func xxh64(data []byte, zeroChecksum bool) uint64 {
	cursor := 0
	var hash uint64
	if len(data) >= 32 {
		v1 := uint64(xxhPrime1)
		v1 += xxhPrime2
		v2 := xxhPrime2
		v3 := uint64(0)
		v4 := uint64(0)
		v4 -= xxhPrime1
		limit := len(data) - 32
		for cursor <= limit {
			v1 = xxhRound(v1, xxhUint64(data, cursor, zeroChecksum))
			v2 = xxhRound(v2, xxhUint64(data, cursor+8, zeroChecksum))
			v3 = xxhRound(v3, xxhUint64(data, cursor+16, zeroChecksum))
			v4 = xxhRound(v4, xxhUint64(data, cursor+24, zeroChecksum))
			cursor += 32
		}
		hash = bits.RotateLeft64(v1, 1) + bits.RotateLeft64(v2, 7) +
			bits.RotateLeft64(v3, 12) + bits.RotateLeft64(v4, 18)
		hash = xxhMerge(hash, v1)
		hash = xxhMerge(hash, v2)
		hash = xxhMerge(hash, v3)
		hash = xxhMerge(hash, v4)
	} else {
		hash = xxhPrime5
	}
	hash += uint64(len(data))
	for cursor+8 <= len(data) {
		hash ^= xxhRound(0, xxhUint64(data, cursor, zeroChecksum))
		hash = bits.RotateLeft64(hash, 27)*xxhPrime1 + xxhPrime4
		cursor += 8
	}
	if cursor+4 <= len(data) {
		hash ^= uint64(xxhUint32(data, cursor, zeroChecksum)) * xxhPrime1
		hash = bits.RotateLeft64(hash, 23)*xxhPrime2 + xxhPrime3
		cursor += 4
	}
	for cursor < len(data) {
		value := data[cursor]
		if zeroChecksum && cursor >= 48 && cursor < 56 {
			value = 0
		}
		hash ^= uint64(value) * xxhPrime5
		hash = bits.RotateLeft64(hash, 11) * xxhPrime1
		cursor++
	}
	hash ^= hash >> 33
	hash *= xxhPrime2
	hash ^= hash >> 29
	hash *= xxhPrime3
	return hash ^ (hash >> 32)
}

func xxhRound(accumulator, input uint64) uint64 {
	accumulator += input * xxhPrime2
	accumulator = bits.RotateLeft64(accumulator, 31)
	return accumulator * xxhPrime1
}

func xxhMerge(accumulator, value uint64) uint64 {
	accumulator ^= xxhRound(0, value)
	return accumulator*xxhPrime1 + xxhPrime4
}

func xxhUint64(data []byte, offset int, zeroChecksum bool) uint64 {
	if !zeroChecksum || offset+8 <= 48 || offset >= 56 {
		return binary.LittleEndian.Uint64(data[offset : offset+8])
	}
	var value uint64
	for index := 0; index < 8; index++ {
		position := offset + index
		if position < 48 || position >= 56 {
			value |= uint64(data[position]) << (index * 8)
		}
	}
	return value
}

func xxhUint32(data []byte, offset int, zeroChecksum bool) uint32 {
	if !zeroChecksum || offset+4 <= 48 || offset >= 56 {
		return binary.LittleEndian.Uint32(data[offset : offset+4])
	}
	var value uint32
	for index := 0; index < 4; index++ {
		position := offset + index
		if position < 48 || position >= 56 {
			value |= uint32(data[position]) << (index * 8)
		}
	}
	return value
}
