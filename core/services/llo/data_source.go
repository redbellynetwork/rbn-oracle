package llo

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	llotypes "github.com/smartcontractkit/chainlink-common/pkg/types/llo"
	"github.com/smartcontractkit/chainlink-data-streams/llo"

	"github.com/smartcontractkit/chainlink/v2/core/logger"
	"github.com/smartcontractkit/chainlink/v2/core/services/pipeline"
	"github.com/smartcontractkit/chainlink/v2/core/services/streams"
)

var (
	promMissingStreamCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "llo_stream_missing_count",
		Help: "Number of times we tried to observe a stream, but it was missing",
	},
		[]string{"streamID"},
	)
	promObservationErrorCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "llo_stream_observation_error_count",
		Help: "Number of times we tried to observe a stream, but it failed with an error",
	},
		[]string{"streamID"},
	)
)

type Registry interface {
	Get(streamID streams.StreamID) (strm streams.Stream, exists bool)
}

type ErrObservationFailed struct {
	id  streams.StreamID
	err string
	run *pipeline.Run
}

func (e ErrObservationFailed) Error() string {
	return e.err
}

func (e ErrObservationFailed) String() string {
	return e.err
}

var _ llo.DataSource = &dataSource{}

type dataSource struct {
	lggr     logger.Logger
	registry Registry
}

func newDataSource(lggr logger.Logger, registry Registry) llo.DataSource {
	return &dataSource{lggr.Named("DataSource"), registry}
}

// Observe looks up all streams in the registry and returns a map of stream ID => value
func (d *dataSource) Observe(ctx context.Context, streamIDs map[llotypes.StreamID]struct{}) (llo.StreamValues, error) {
	// TODO: pass seqnr for more helpful logging
	var wg sync.WaitGroup
	wg.Add(len(streamIDs))
	sv := make(llo.StreamValues)
	var svmu sync.Mutex
	var errors []ErrObservationFailed
	var errmu sync.Mutex

	d.lggr.Debugw("Observing streams", "streamIDs", streamIDs)

	for streamID := range streamIDs {
		go func(streamID llotypes.StreamID) {
			defer wg.Done()

			var res llo.ObsResult[*big.Int]

			stream, exists := d.registry.Get(streamID)
			if exists {
				run, trrs, err := stream.Run(ctx)
				if err != nil {
					errmu.Lock()
					errors = append(errors, ErrObservationFailed{run: run, id: streamID, err: fmt.Errorf("observation failed for stream %d: %w", streamID, err).Error()})
					errmu.Unlock()
					promObservationErrorCount.WithLabelValues(fmt.Sprintf("%d", streamID)).Inc()
				} else {
					// TODO: support types other than *big.Int
					// https://smartcontract-it.atlassian.net/browse/MERC-3525
					val, err := streams.ExtractBigInt(trrs)
					if err == nil {
						res.Val = val
						res.Valid = true
					}
				}
			} else {
				errmu.Lock()
				errors = append(errors, ErrObservationFailed{id: streamID, err: fmt.Sprintf("missing stream: %d", streamID)})
				errmu.Unlock()
				promMissingStreamCount.WithLabelValues(fmt.Sprintf("%d", streamID)).Inc()
			}

			svmu.Lock()
			defer svmu.Unlock()
			sv[streamID] = res
		}(streamID)
	}

	wg.Wait()

	var failedStreamIDs []streams.StreamID
	if len(errors) > 0 {
		failedStreamIDs = make([]streams.StreamID, len(errors))
		for i, e := range errors {
			failedStreamIDs[i] = e.id
		}
		sort.Slice(failedStreamIDs, func(i, j int) bool { return failedStreamIDs[i] < failedStreamIDs[j] })
		d.lggr.Warnw("Observation failed for streams", "streamIDs", failedStreamIDs, "errors", errors)
	}

	successes := make([]streams.StreamID, 0, len(sv))
	for strmID, res := range sv {
		if res.Valid {
			successes = append(successes, strmID)
		}
	}
	sort.Slice(successes, func(i, j int) bool { return successes[i] < successes[j] })
	d.lggr.Debugw("Observation complete", "successfulStreamIDs", successes, "failedStreamIDs", failedStreamIDs, "values", sv)

	return sv, nil
}
