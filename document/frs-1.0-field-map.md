# FRS 1.0 field map

This document is the implementation field map used by frs-tool. All integers are fixed-width little-endian values. Offsets and lengths are bytes from the start of the file unless stated otherwise.

## File header

The header is 64 bytes.

| Offset | Size | Field | FRS 1.0 value or rule |
|---:|---:|---|---|
| 0 | 8 | magic | `FTUNFRS` followed by NUL |
| 8 | 2 | major | 1 |
| 10 | 2 | minor | 0 |
| 12 | 4 | header_bytes | 64 |
| 16 | 4 | required_features | bit 0 IPv4, bit 1 domain radix, bit 2 keyword; bit 3 reserved and zero |
| 20 | 4 | section_count | number of 40-byte directory entries |
| 24 | 8 | file_bytes | exact file length |
| 32 | 8 | directory_offset | 64 |
| 40 | 8 | reserved0 | zero |
| 48 | 8 | file_checksum | XXH64 with seed 0; bytes 48–55 are treated as zero during calculation |
| 56 | 8 | reserved1 | zero |

## Section directory

Each directory entry is 40 bytes.

| Entry offset | Size | Field |
|---:|---:|---|
| 0 | 4 | type |
| 4 | 4 | flags; known sections use mandatory bit 0 |
| 8 | 8 | section offset |
| 16 | 8 | byte length |
| 24 | 8 | record count, or byte count for STRINGS |
| 32 | 4 | record stride |
| 36 | 4 | reserved; zero |

Known sections are unique and sorted by type:

| Type | Name | Stride |
|---:|---|---:|
| 1 | SETS | 64 |
| 2 | STRINGS | 1 |
| 3 | IPV4_RANGES | 8 |
| 4 | DOMAIN_NODES | 16 |
| 5 | DOMAIN_EDGES | 16 |
| 6 | KEYWORDS | 16 |
| 7 | IPV6_RANGES | reserved and absent in 1.0 |

The SETS section is always present and may be empty. Other empty semantic sections are omitted. Sections and the first payload are aligned to 8 bytes; padding is zero.

## SETS record

Each record is 64 bytes. IDs and span starts are 1-based; an empty span has start and count both zero.

| Record offset | Size | Field |
|---:|---:|---|
| 0 | 4 | set_id; 1-based row number |
| 4 | 2 | kind; 1 IPv4, 2 domain |
| 6 | 2 | flags; zero |
| 8 | 8 | label_offset relative to STRINGS |
| 16 | 4 | label_length |
| 20 | 4 | reserved; zero |
| 24 | 4 | a_start |
| 28 | 4 | a_count |
| 32 | 4 | b_start |
| 36 | 4 | b_count |
| 40 | 4 | c_start |
| 44 | 4 | c_count |
| 48 | 4 | root_node |
| 52 | 4 | encoding; 1 IPv4 ranges, 2 domain radix plus keywords |
| 56 | 8 | reserved; zero |

For IPv4 sets, span A references IPV4_RANGES and all other spans and root are zero. For domain sets, spans A, B, and C reference DOMAIN_NODES, DOMAIN_EDGES, and KEYWORDS; root_node is the first node ID when a trie exists.

## Index records

| Section | Offset | Size | Field |
|---|---:|---:|---|
| IPV4_RANGES | 0 | 4 | IPv4 numeric lower bound |
| IPV4_RANGES | 4 | 4 | IPv4 numeric upper bound |
| DOMAIN_NODES | 0 | 4 | 1-based edge_start |
| DOMAIN_NODES | 4 | 4 | edge_count |
| DOMAIN_NODES | 8 | 4 | terminal flags: bit 0 exact, bit 1 suffix |
| DOMAIN_NODES | 12 | 4 | reserved; zero |
| DOMAIN_EDGES | 0 | 8 | reversed ASCII label offset in STRINGS |
| DOMAIN_EDGES | 8 | 4 | label length |
| DOMAIN_EDGES | 12 | 4 | 1-based child node ID |
| KEYWORDS | 0 | 8 | keyword offset in STRINGS |
| KEYWORDS | 8 | 4 | keyword length |
| KEYWORDS | 12 | 4 | reserved; zero |

IPv4 values use the numeric form `(a<<24)|(b<<16)|(c<<8)|d` and are then encoded little-endian. Domain edge labels store reversed normalized ASCII byte fragments. STRINGS contains exact complete fragments without NUL terminators.

## Canonical ordering

Sets are ordered by kind and then normalized UTF-8 label bytes. IPv4 intervals are sorted and merge overlap or adjacency. Trie nodes and edges use deterministic parent/child ordering. Keywords and string fragments are byte-sorted and deduplicated as complete fragments. Source metadata, timestamps, and diagnostics never enter the binary payload.

The empty-container golden vector in `testdata/frs/empty-v1.golden.hex` is 104 bytes: the header plus one empty SETS directory entry. It is a format fixture, not a buildable all-empty result.
