package google

import (
	"context"
	"sync"
	"time"
)

type CachingCertFetcher struct {
	certsLock sync.Mutex
	certs     *PublicCerts
	wrapped   CertFetcher
}

func (c *CachingCertFetcher) FetchCerts(ctx context.Context) (PublicCerts, error) {
	c.certsLock.Lock()
	defer c.certsLock.Unlock()

	if c.certs == nil || c.certs.Expiration.Before(time.Now()) {
		newCerts, err := c.wrapped.FetchCerts(ctx)
		if err != nil {
			return PublicCerts{}, err
		} else {
			c.certs = &newCerts
		}
	}

	return *c.certs, nil
}

func NewCachingCertFetcher(fetcher CertFetcher) *CachingCertFetcher {
	return &CachingCertFetcher{
		certsLock: sync.Mutex{},
		wrapped:   fetcher,
	}
}
