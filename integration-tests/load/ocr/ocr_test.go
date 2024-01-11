package ocr

import (
	"github.com/rs/zerolog"
	"github.com/smartcontractkit/havoc"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/wasp"

	"github.com/smartcontractkit/chainlink-testing-framework/logging"

	"github.com/smartcontractkit/chainlink/integration-tests/k8s"
)

var (
	CommonTestLabels = map[string]string{
		"branch": "ocr_healthcheck_local",
		"commit": "ocr_healthcheck_local",
	}
)

func createMonkey(t *testing.T, l zerolog.Logger, namespace string) *havoc.Controller {
	havoc.SetGlobalLogger(l)
	cfg, err := havoc.ReadConfig(DefaultConfigFilename)
	require.NoError(t, err)
	c, err := havoc.NewController(cfg)
	err = c.GenerateSpecs(namespace)
	require.NoError(t, err)
	return c
}

func TestOCRLoad(t *testing.T) {
	l := logging.GetTestLogger(t)
	cc, msClient, cd, bootstrapNode, workerNodes, err := k8s.ConnectRemote(l)
	require.NoError(t, err)
	lt, err := SetupClusterContracts(cc, cd, workerNodes)
	require.NoError(t, err)
	ocrInstances, err := SetupFeed(cc, msClient, cd, bootstrapNode, workerNodes, lt)
	require.NoError(t, err)
	cfg, err := ReadConfig()
	require.NoError(t, err)
	SimulateEAActivity(l, cfg.Load.EAChangeInterval.Duration(), ocrInstances, workerNodes, msClient)

	p := wasp.NewProfile()
	p.Add(wasp.NewGenerator(&wasp.Config{
		T:                     t,
		GenName:               "ocr",
		LoadType:              wasp.RPS,
		CallTimeout:           cfg.Load.VerificationTimeout.Duration(),
		RateLimitUnitDuration: cfg.Load.RateLimitUnitDuration.Duration(),
		Schedule:              wasp.Plain(cfg.Load.Rate, cfg.Load.TestDuration.Duration()),
		Gun:                   NewGun(l, cc, ocrInstances),
		Labels:                CommonTestLabels,
		LokiConfig:            wasp.NewEnvLokiConfig(),
	}))
	monkey := createMonkey(t, l, cfg.Env.Namespace)
	go monkey.Run()
	_, err = p.Run(true)
	require.NoError(t, err)
	errs := monkey.Stop()
	require.Len(t, errs, 0)
}

func TestOCRVolume(t *testing.T) {
	l := logging.GetTestLogger(t)
	cc, msClient, cd, bootstrapNode, workerNodes, err := k8s.ConnectRemote(l)
	require.NoError(t, err)
	lt, err := SetupClusterContracts(cc, cd, workerNodes)
	require.NoError(t, err)
	cfg, err := ReadConfig()
	require.NoError(t, err)

	p := wasp.NewProfile()
	p.Add(wasp.NewGenerator(&wasp.Config{
		T:           t,
		GenName:     "ocr",
		LoadType:    wasp.VU,
		CallTimeout: cfg.Volume.VerificationTimeout.Duration(),
		Schedule:    wasp.Plain(cfg.Volume.Rate, cfg.Volume.TestDuration.Duration()),
		VU:          NewVU(l, cfg.Volume.VURequestsPerUnit, cfg.Volume.RateLimitUnitDuration.Duration(), cc, lt, cd, bootstrapNode, workerNodes, msClient),
		Labels:      CommonTestLabels,
		LokiConfig:  wasp.NewEnvLokiConfig(),
	}))
	monkey := createMonkey(t, l, cfg.Env.Namespace)
	go monkey.Run()
	_, err = p.Run(true)
	require.NoError(t, err)
	errs := monkey.Stop()
	require.Len(t, errs, 0)
}
