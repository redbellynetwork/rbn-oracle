package cmd

type Test struct {
	Name string
	Path string
}

// CITestConf defines the configuration for running a test in a CI environment, specifying details like test ID, path, type, runner settings, command, and associated workflows.
type CITestConf struct {
	ID                    string             `yaml:"id" json:"id"`
	IDSanitized           string             `json:"idSanitized"`
	Path                  string             `yaml:"path" json:"path"`
	TestType              string             `yaml:"test-type" json:"testType"`
	RunsOn                string             `yaml:"runs-on" json:"runsOn"`
	TestCmd               string             `yaml:"test-cmd" json:"testCmd"`
	TestConfigOverride    TestConfigOverride `yaml:"test-config-override" json:"testConfigOverride"`
	RemoteRunnerTestSuite string             `yaml:"remote-runner-test-suite" json:"remoteRunnerTestSuite"`
	RemoteRunnerMemory    string             `yaml:"remote-runner-memory" json:"remoteRunnerMemory"`
	PyroscopeEnv          string             `yaml:"pyroscope-env" json:"pyroscopeEnv"`
	Workflows             []string           `yaml:"workflows" json:"workflows"`
}

type TestConfigOverride struct {
	ChainlinkUpgradeImage   string `yaml:"chainlink-upgrade-image" json:"chainlinkUpgradeImage"`
	ChainlinkUpgradeVersion string `yaml:"chainlink-upgrade-version" json:"chainlinkUpgradeVersion"`
	ChainlinkImage          string `yaml:"chainlink-image" json:"chainlinkImage"`
	ChainlinkVersion        string `yaml:"chainlink-version" json:"chainlinkVersion"`
}

type Config struct {
	Tests []CITestConf `yaml:"runner-test-matrix"`
}