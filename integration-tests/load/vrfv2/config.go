package loadvrfv2

import (
	"encoding/base64"
	"fmt"
	"github.com/smartcontractkit/chainlink/integration-tests/actions/vrfv2/vrfv2_config"
	"os"

	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog/log"
	"github.com/smartcontractkit/chainlink/v2/core/store/models"
)

const (
	DefaultConfigFilename = "config.toml"
	SoakTestType          = "Soak"
	LoadTestType          = "Load"
	StressTestType        = "Stress"
	SpikeTestType         = "Spike"

	ErrReadPerfConfig                    = "failed to read TOML config for performance tests"
	ErrUnmarshalPerfConfig               = "failed to unmarshal TOML config for performance tests"
	ErrDeviationShouldBeLessThanOriginal = "`RandomnessRequestCountPerRequestDeviation` should be less than `RandomnessRequestCountPerRequest`"
)

type PerformanceConfig struct {
	Soak   *Soak   `toml:"Soak"`
	Load   *Load   `toml:"Load"`
	Stress *Stress `toml:"Stress"`
	Spike  *Spike  `toml:"Spike"`

	Common            *Common            `toml:"Common"`
	ExistingEnvConfig *ExistingEnvConfig `toml:"ExistingEnvConfig"`
	NewEnvConfig      *NewEnvConfig      `toml:"NewEnvConfig"`
}

type ExistingEnvConfig struct {
	CoordinatorAddress string `toml:"coordinator_address"`
	ConsumerAddress    string `toml:"consumer_address"`
	LinkAddress        string `toml:"link_address"`
	SubID              uint64 `toml:"sub_id"`
	KeyHash            string `toml:"key_hash"`
	SubFunding
	CreateFundSubsAndAddConsumers bool `toml:"create_fund_subs_and_add_consumers"`
}

type NewEnvConfig struct {
	Funding
}

type Common struct {
	MinimumConfirmations uint16 `toml:"minimum_confirmations"`
}

type Funding struct {
	NodeFunds float64 `toml:"node_funds"`
	SubFunding
}

type SubFunding struct {
	SubFundsLink   float64 `toml:"sub_funds_link"`
	SubFundsNative float64 `toml:"sub_funds_native"`
}

type Soak struct {
	PerformanceTestConfig
}

type Load struct {
	PerformanceTestConfig
}

type Stress struct {
	PerformanceTestConfig
}

type Spike struct {
	PerformanceTestConfig
}

type PerformanceTestConfig struct {
	NumberOfSubToCreate int `toml:"number_of_sub_to_create"`

	RPS int64 `toml:"rps"`
	//Duration *models.Duration `toml:"duration"`
	RateLimitUnitDuration                     *models.Duration `toml:"rate_limit_unit_duration"`
	RandomnessRequestCountPerRequest          uint16           `toml:"randomness_request_count_per_request"`
	RandomnessRequestCountPerRequestDeviation uint16           `toml:"randomness_request_count_per_request_deviation"`
}

func ReadConfig() (*PerformanceConfig, error) {
	var cfg *PerformanceConfig
	rawConfig := os.Getenv("CONFIG")
	var d []byte
	var err error
	if rawConfig == "" {
		d, err = os.ReadFile(DefaultConfigFilename)
		if err != nil {
			return nil, fmt.Errorf("%s, err: %w", ErrReadPerfConfig, err)
		}
	} else {
		d, err = base64.StdEncoding.DecodeString(rawConfig)
	}
	err = toml.Unmarshal(d, &cfg)
	if err != nil {
		return nil, fmt.Errorf("%s, err: %w", ErrUnmarshalPerfConfig, err)
	}

	if cfg.Soak.RandomnessRequestCountPerRequest <= cfg.Soak.RandomnessRequestCountPerRequestDeviation {
		return nil, fmt.Errorf("%s, err: %w", ErrDeviationShouldBeLessThanOriginal, err)
	}

	log.Debug().Interface("Config", cfg).Msg("Parsed config")
	return cfg, nil
}

func SetPerformanceTestConfig(testType string, vrfv2Config *vrfv2_config.VRFV2Config, cfg *PerformanceConfig) {
	switch testType {
	case SoakTestType:
		vrfv2Config.NumberOfSubToCreate = cfg.Soak.NumberOfSubToCreate
		vrfv2Config.RPS = cfg.Soak.RPS
		vrfv2Config.RateLimitUnitDuration = cfg.Soak.RateLimitUnitDuration.Duration()
		vrfv2Config.RandomnessRequestCountPerRequest = cfg.Soak.RandomnessRequestCountPerRequest
		vrfv2Config.RandomnessRequestCountPerRequestDeviation = cfg.Soak.RandomnessRequestCountPerRequestDeviation
	case LoadTestType:
		vrfv2Config.NumberOfSubToCreate = cfg.Load.NumberOfSubToCreate
		vrfv2Config.RPS = cfg.Load.RPS
		vrfv2Config.RateLimitUnitDuration = cfg.Load.RateLimitUnitDuration.Duration()
		vrfv2Config.RandomnessRequestCountPerRequest = cfg.Load.RandomnessRequestCountPerRequest
		vrfv2Config.RandomnessRequestCountPerRequestDeviation = cfg.Load.RandomnessRequestCountPerRequestDeviation
	case StressTestType:
		vrfv2Config.NumberOfSubToCreate = cfg.Stress.NumberOfSubToCreate
		vrfv2Config.RPS = cfg.Stress.RPS
		vrfv2Config.RateLimitUnitDuration = cfg.Stress.RateLimitUnitDuration.Duration()
		vrfv2Config.RandomnessRequestCountPerRequest = cfg.Stress.RandomnessRequestCountPerRequest
		vrfv2Config.RandomnessRequestCountPerRequestDeviation = cfg.Stress.RandomnessRequestCountPerRequestDeviation
	case SpikeTestType:
		vrfv2Config.NumberOfSubToCreate = cfg.Spike.NumberOfSubToCreate
		vrfv2Config.RPS = cfg.Spike.RPS
		vrfv2Config.RateLimitUnitDuration = cfg.Spike.RateLimitUnitDuration.Duration()
		vrfv2Config.RandomnessRequestCountPerRequest = cfg.Spike.RandomnessRequestCountPerRequest
		vrfv2Config.RandomnessRequestCountPerRequestDeviation = cfg.Spike.RandomnessRequestCountPerRequestDeviation
	}
}
