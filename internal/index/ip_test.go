package index

import (
	"math/rand"
	"net/netip"
	"testing"

	"frs-tool/internal/model"
)

func TestBuildIPv4MergesOverlapAndAdjacency(t *testing.T) {
	t.Parallel()
	records := []model.Record{
		ipRecord("10.0.0.0/25"),
		ipRecord("10.0.0.128/25"),
		ipRecord("10.0.0.0/24"),
		ipRecord("192.0.2.1/32"),
		ipRecord("192.0.2.2/32"),
	}
	index, err := BuildIPv4(records)
	if err != nil {
		t.Fatal(err)
	}
	if index.PrefixCount != 5 {
		t.Fatalf("prefix count = %d", index.PrefixCount)
	}
	if len(index.Ranges) != 2 {
		t.Fatalf("ranges = %+v", index.Ranges)
	}
	for _, value := range []string{"10.0.0.0", "10.0.0.255", "192.0.2.1", "192.0.2.2"} {
		if !index.Contains(netip.MustParseAddr(value)) {
			t.Errorf("%s did not match", value)
		}
	}
	for _, value := range []string{"10.0.1.0", "192.0.2.3", "2001:db8::1"} {
		if index.Contains(netip.MustParseAddr(value)) {
			t.Errorf("%s unexpectedly matched", value)
		}
	}
}

func TestIPv4IndexRandomDifferential(t *testing.T) {
	t.Parallel()
	random := rand.New(rand.NewSource(42))
	var records []model.Record
	var prefixes []netip.Prefix
	for count := 0; count < 300; count++ {
		address := netip.AddrFrom4([4]byte{
			byte(random.Intn(256)),
			byte(random.Intn(256)),
			byte(random.Intn(256)),
			byte(random.Intn(256)),
		})
		prefix := netip.PrefixFrom(address, random.Intn(33)).Masked()
		prefixes = append(prefixes, prefix)
		records = append(records, model.Record{Kind: model.RuleIPv4, Prefix: prefix})
	}
	index, err := BuildIPv4(records)
	if err != nil {
		t.Fatal(err)
	}
	for count := 0; count < 5000; count++ {
		address := netip.AddrFrom4([4]byte{
			byte(random.Intn(256)),
			byte(random.Intn(256)),
			byte(random.Intn(256)),
			byte(random.Intn(256)),
		})
		expected := false
		for _, prefix := range prefixes {
			if prefix.Contains(address) {
				expected = true
				break
			}
		}
		if actual := index.Contains(address); actual != expected {
			t.Fatalf("Contains(%s) = %v, want %v", address, actual, expected)
		}
	}
}

func ipRecord(value string) model.Record {
	return model.Record{Kind: model.RuleIPv4, Prefix: netip.MustParsePrefix(value)}
}
