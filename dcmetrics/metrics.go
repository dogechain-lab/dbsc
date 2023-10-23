package dcmetrics

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/dogechain-lab/dogechain/blockchain"
	"github.com/dogechain-lab/dogechain/consensus"
	itrie "github.com/dogechain-lab/dogechain/state/immutable-trie"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "dc_dbsc"

var (
	ChainID = "2000" // chain id
)

var (
	sharedOnce    sync.Once
	sharedMetrics *DCMetrics
)

// DCMetrics holds the metric instances of dc sub systems
type DCMetrics struct {
	Blockchain *blockchain.Metrics
	Consensus  *consensus.Metrics
	Trie       itrie.Metrics
}

func SharedMetrics() *DCMetrics {
	sharedOnce.Do(func() {
		if metrics.Enabled {
			sharedMetrics = &DCMetrics{
				Blockchain: blockchain.GetPrometheusMetrics(namespace, "chain_id", ChainID),
				Consensus:  consensus.GetPrometheusMetrics(namespace, "chain_id", ChainID),
				Trie:       itrie.GetPrometheusMetrics(namespace, metrics.EnabledExpensive, "chain_id", ChainID),
			}
		} else {
			sharedMetrics = &DCMetrics{
				Blockchain: blockchain.NilMetrics(),
				Consensus:  consensus.NilMetrics(),
				Trie:       itrie.NilMetrics(),
			}
		}
	})

	return sharedMetrics
}

func StartPrometheusServer(addr string) *http.Server {
	srv := &http.Server{
		Addr: addr,
		Handler: promhttp.InstrumentMetricHandler(
			prometheus.DefaultRegisterer, promhttp.HandlerFor(
				prometheus.DefaultGatherer,
				promhttp.HandlerOpts{},
			),
		),
		ReadHeaderTimeout: time.Minute,
	}

	go func() {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Error("DC prometheus http server ListenAndServe failed", "err", err)
		} else {
			log.Info("DC prometheus http server stop")
		}
	}()

	return srv
}
