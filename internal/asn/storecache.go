package asn

import (
	"encoding/json"

	"github.com/nyktios/sniroute/internal/store"
)

// StoreCache keeps lookups in the SQLite store.
type StoreCache struct{ st *store.Store }

// NewStoreCache adapts the store to the Cache interface.
func NewStoreCache(st *store.Store) *StoreCache { return &StoreCache{st: st} }

// Get implements Cache.
func (c *StoreCache) Get(source, ip string) (Info, bool, error) {
	row, ok, err := c.st.GetASNCache(source, ip)
	if err != nil || !ok {
		return Info{}, false, err
	}
	var i Info
	if err := json.Unmarshal([]byte(row.Result), &i); err != nil {
		return Info{}, false, nil // an unreadable entry is a miss
	}
	i.QueriedAt = row.QueriedAt
	return i, true, nil
}

// Put implements Cache.
func (c *StoreCache) Put(i Info) error {
	b, err := json.Marshal(i)
	if err != nil {
		return err
	}
	return c.st.PutASNCache(store.ASNRow{IP: i.IP, Source: i.Source, QueriedAt: i.QueriedAt, Status: string(i.Status), Result: string(b)})
}
