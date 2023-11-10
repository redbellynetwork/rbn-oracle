package smoke

import (
	"context"
	"github.com/kelseyhightower/envconfig"
	"github.com/smartcontractkit/chainlink/integration-tests/actions/vrfv2"
	"github.com/smartcontractkit/chainlink/integration-tests/actions/vrfv2/vrfv2_config"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"

	"github.com/smartcontractkit/chainlink-testing-framework/logging"

	"github.com/smartcontractkit/chainlink/integration-tests/actions"
	"github.com/smartcontractkit/chainlink/integration-tests/docker/test_env"
)

func TestVRFv2Basic(t *testing.T) {
	t.Parallel()
	l := logging.GetTestLogger(t)

	var vrfv2Config vrfv2_config.VRFV2Config
	err := envconfig.Process("VRFV2", &vrfv2Config)
	require.NoError(t, err)

	env, err := test_env.NewCLTestEnvBuilder().
		WithTestLogger(t).
		WithGeth().
		WithCLNodes(1).
		WithFunding(big.NewFloat(vrfv2Config.ChainlinkNodeFunding)).
		WithStandardCleanup().
		Build()
	require.NoError(t, err, "error creating test env")

	env.ParallelTransactions(true)

	mockETHLinkFeed, err := actions.DeployMockETHLinkFeed(env.ContractDeployer, big.NewInt(vrfv2Config.LinkNativeFeedResponse))
	require.NoError(t, err)
	linkToken, err := actions.DeployLINKToken(env.ContractDeployer)
	require.NoError(t, err)

	// register proving key against oracle address (sending key) in order to test oracleWithdraw
	defaultWalletAddress := env.EVMClient.GetDefaultWallet().Address()

	vrfv2Contracts, subIDs, vrfv2Data, err := vrfv2.SetupVRFV2Environment(
		env,
		vrfv2Config,
		linkToken,
		mockETHLinkFeed,
		defaultWalletAddress,
		1,
		1,
		l,
	)
	require.NoError(t, err, "error setting up VRF v2 env")

	subID := subIDs[0]

	subscription, err := vrfv2Contracts.Coordinator.GetSubscription(context.Background(), subID)
	require.NoError(t, err, "error getting subscription information")

	vrfv2.LogSubDetails(l, subscription, subID, vrfv2Contracts.Coordinator)

	t.Run("Request Randomness", func(t *testing.T) {
		testConfig := vrfv2Config
		var isNativeBilling = false
		subBalanceBeforeRequest := subscription.Balance

		jobRunsBeforeTest, err := env.ClCluster.Nodes[0].API.MustReadRunsByJob(vrfv2Data.VRFJob.Data.ID)
		require.NoError(t, err, "error reading job runs")

		// test and assert
		randomWordsFulfilledEvent, err := vrfv2.RequestRandomnessAndWaitForFulfillment(
			vrfv2Contracts.LoadTestConsumers[0],
			vrfv2Contracts.Coordinator,
			vrfv2Data,
			subID,
			isNativeBilling,
			testConfig.RandomnessRequestCountPerRequest,
			testConfig,
			testConfig.RandomWordsFulfilledEventTimeout,
			l,
		)
		require.NoError(t, err, "error requesting randomness and waiting for fulfilment")

		expectedSubBalanceJuels := new(big.Int).Sub(subBalanceBeforeRequest, randomWordsFulfilledEvent.Payment)
		subscription, err = vrfv2Contracts.Coordinator.GetSubscription(context.Background(), subID)
		require.NoError(t, err, "error getting subscription information")
		subBalanceAfterRequest := subscription.Balance
		require.Equal(t, expectedSubBalanceJuels, subBalanceAfterRequest)

		jobRuns, err := env.ClCluster.Nodes[0].API.MustReadRunsByJob(vrfv2Data.VRFJob.Data.ID)
		require.NoError(t, err, "error reading job runs")
		require.Equal(t, len(jobRunsBeforeTest.Data)+1, len(jobRuns.Data))

		status, err := vrfv2Contracts.LoadTestConsumers[0].GetRequestStatus(context.Background(), randomWordsFulfilledEvent.RequestId)
		require.NoError(t, err, "error getting rand request status")
		require.True(t, status.Fulfilled)
		l.Debug().Bool("Fulfilment Status", status.Fulfilled).Msg("Random Words Request Fulfilment Status")

		require.Equal(t, testConfig.NumberOfWords, uint32(len(status.RandomWords)))
		for _, w := range status.RandomWords {
			l.Info().Str("Output", w.String()).Msg("Randomness fulfilled")
			require.Equal(t, 1, w.Cmp(big.NewInt(0)), "Expected the VRF job give an answer bigger than 0")
		}
	})
}
