// Native Go implementation for Braiins OS evcc integration
// https://developer.braiins-os.com/latest/openapi.html
// For dynamic power control: Enable "Power Target" mode in Braiins OS tuner settings
// Without Power Target: Only on/off control available
// Also enable DPS-Mode if needed
// Version: 0.1
//
// LICENSE
// Copyright (c) Tobias W. Huber https://github.com/TobiasHuber1980/
// This module is NOT covered by the MIT license. All rights reserved.

package charger

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/evcc-io/evcc/api"
	"github.com/evcc-io/evcc/core/loadpoint"
	"github.com/evcc-io/evcc/util"
	"github.com/evcc-io/evcc/util/request"
)

// Miner status constants
const (
	MinerStatusUnspecified = 0
	MinerStatusIdle        = 1
	MinerStatusMining      = 2
	MinerStatusPaused      = 3
	MinerStatusDegraded    = 4
	MinerStatusError       = 5
)

// API endpoint paths
const (
	apiPathLogin         = "/api/v1/auth/login"
	apiPathMinerDetails  = "/api/v1/miner/details"
	apiPathMinerStats    = "/api/v1/miner/stats"
	apiPathPause         = "/api/v1/actions/pause"
	apiPathResume        = "/api/v1/actions/resume"
	apiPathConstraints   = "/api/v1/configuration/constraints"
	apiPathMinerConfig   = "/api/v1/configuration/miner"
	apiPathPowerTarget   = "/api/v1/performance/power-target"
	apiPathNetworkConfig = "/api/v1/network/configuration"
)

// Power control constants
const (
	defaultTimeout              = 15 * time.Second
	defaultVoltage              = 230.0
	defaultPowerTargetStep      = 300
	defaultMinDecreaseDuration  = 5 * time.Minute // Changed from 15min to 5min
	defaultDecreaseStepInterval = 3 * time.Minute // Changed from 5min to 3min
	defaultConsistencyChecks    = 5
	defaultRecentRequestsLimit  = 10

	lowPowerThreshold        = 0.85
	requiredConsistencyRatio = 0.80
	tokenExpiryBufferSeconds = 30
	defaultTokenTimeout      = 1 * time.Hour
)

// Daily reset timing
const (
	dailyResetHour   = 23
	dailyResetMinute = 59
)

// BraiinsOS implements the Charger interface for Braiins OS miners
type BraiinsOS struct {
	*request.Helper
	*embed

	uri      string
	user     string
	password string

	config   PowerControlConfig
	hardware HardwareCapabilities

	powerState          PowerTargetState
	dps                 DPSState
	intelligentDecrease IntelligentDecreaseController

	auth    AuthState
	session SessionState

	lp          loadpoint.API
	currentMode api.ChargeMode
	log         *util.Logger
	mu          sync.Mutex
}

// PowerControlConfig holds user configuration
type PowerControlConfig struct {
	MaxPower          int
	Voltage           float64
	PowerTargetStep   int
	DailyResetEnabled bool
}

// HardwareCapabilities represents miner hardware limits
type HardwareCapabilities struct {
	MinWatts     int
	DefaultWatts int
	MaxWatts     int
	Name         string
}

// PowerTargetState tracks power target status
type PowerTargetState struct {
	Enabled         bool
	LastTarget      int
	LastUpdate      time.Time
	WarningShown    bool
	IsPausing       bool
	PauseStarted    time.Time
	IsFromDiscovery bool
	PausedByTimer   bool
}

// DPSState tracks Dynamic Power Scaling state
type DPSState struct {
	Detected   bool
	Active     bool
	MinTarget  int
	ActiveStep int
}

// IntelligentDecreaseController manages gradual power decreases
type IntelligentDecreaseController struct {
	Enabled              bool
	MinDecreaseDuration  time.Duration
	DecreaseStepInterval time.Duration
	ConsistencyChecks    int

	LowPowerStart    time.Time
	LastDecreaseStep time.Time

	LastTimer1LoggedMinute int
	LastTimer2LoggedMinute int
	LoggedFirstExpiry      bool

	RecentRequests     [defaultRecentRequestsLimit]float64
	RecentRequestTimes [defaultRecentRequestsLimit]time.Time
	RequestIndex       int
	RequestCount       int
}

// AuthState manages authentication tokens
type AuthState struct {
	Token       string
	TokenExpiry time.Time
}

// SessionState manages daily resets
type SessionState struct {
	DailyResetDone bool
}

// BraiinsConfig is the configuration structure for unmarshaling
type BraiinsConfig struct {
	URI                  string        `mapstructure:"uri"`
	User                 string        `mapstructure:"user"`
	Password             string        `mapstructure:"password"`
	Timeout              time.Duration `mapstructure:"timeout"`
	MaxPower             int           `mapstructure:"maxPower"`
	Voltage              float64       `mapstructure:"voltage"`
	PowerTargetStep      int           `mapstructure:"powerTargetStep"`
	PowerTargetInterval  time.Duration `mapstructure:"powerTargetInterval"`
	DailyReset           bool          `mapstructure:"dailyReset"`
	IntelligentDecrease  bool          `mapstructure:"intelligentDecrease"`
	MinDecreaseDuration  time.Duration `mapstructure:"minDecreaseDuration"`
	DecreaseStepInterval time.Duration `mapstructure:"decreaseStepInterval"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token    string `json:"token"`
	TimeoutS int    `json:"timeout_s"`
}

type MinerDetails struct {
	Status int `json:"status"`
}

type MinerStats struct {
	PowerStats struct {
		ApproximatedConsumption struct {
			Watt int `json:"watt"`
		} `json:"approximated_consumption"`
	} `json:"power_stats"`
}

type PowerTarget struct {
	Watt int `json:"watt"`
}

type NetworkConfiguration struct {
	Hostname string         `json:"hostname"`
	Protocol map[string]any `json:"protocol,omitempty"`
}

type MinerConfiguration struct {
	DPS struct {
		Enabled   bool `json:"enabled"`
		PowerStep struct {
			Watt int `json:"watt"`
		} `json:"power_step"`
		MinPowerTarget *struct {
			Watt int `json:"watt"`
		} `json:"min_power_target"`
		Mode int `json:"mode"`
	} `json:"dps"`
	Tuner struct {
		Enabled     bool `json:"enabled"`
		TunerMode   int  `json:"tuner_mode"`
		PowerTarget *struct {
			Watt int `json:"watt"`
		} `json:"power_target"`
	} `json:"tuner"`
}

type ConfigConstraints struct {
	TunerConstraints struct {
		PowerTarget struct {
			Min struct {
				Watt int `json:"watt"`
			} `json:"min"`
			Default struct {
				Watt int `json:"watt"`
			} `json:"default"`
			Max struct {
				Watt int `json:"watt"`
			} `json:"max"`
		} `json:"power_target"`
		Enabled struct {
			Default bool `json:"default"`
		} `json:"enabled"`
	} `json:"tuner_constraints"`

	DPSConstraints struct {
		PowerStep struct {
			Default struct {
				Watt int `json:"watt"`
			} `json:"default"`
		} `json:"power_step"`
		MinPowerTarget struct {
			Default struct {
				Watt int `json:"watt"`
			} `json:"default"`
		} `json:"min_power_target"`
		Enabled struct {
			Default bool `json:"default"`
		} `json:"enabled"`
		Mode int `json:"mode"`
	} `json:"dps_constraints"`
}

func init() {
	registry.Add("braiins", NewBraiinsFromConfig)
}

func ensureScheme(u string) string {
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	return "http://" + u
}

func NewBraiinsFromConfig(other map[string]any) (api.Charger, error) {
	cc := applyConfigDefaults(other)
	uri := ensureScheme(cc.URI)
	return NewBraiins(uri, cc.User, cc.Password, cc.Timeout, cc.MaxPower, cc.Voltage,
		cc.PowerTargetStep, cc.DailyReset,
		cc.IntelligentDecrease, cc.MinDecreaseDuration, cc.DecreaseStepInterval)
}

func applyConfigDefaults(other map[string]any) BraiinsConfig {
	var cc BraiinsConfig
	if err := util.DecodeOther(other, &cc); err != nil {
		return cc
	}
	if cc.Timeout == 0 {
		cc.Timeout = defaultTimeout
	}
	if cc.User == "" {
		cc.User = "root"
	}
	if cc.Voltage == 0 {
		cc.Voltage = defaultVoltage
	}
	if cc.PowerTargetStep == 0 {
		cc.PowerTargetStep = defaultPowerTargetStep
	}
	if cc.MinDecreaseDuration == 0 {
		cc.MinDecreaseDuration = defaultMinDecreaseDuration
	}
	if cc.DecreaseStepInterval == 0 {
		cc.DecreaseStepInterval = defaultDecreaseStepInterval
	}
	return cc
}

func NewBraiins(uri, user, password string, timeout time.Duration, maxPower int, voltage float64,
	powerTargetStep int, dailyReset bool,
	intelligentDecrease bool, minDecreaseDuration time.Duration, decreaseStepInterval time.Duration) (api.Charger, error) {
	log := util.NewLogger("braiins")

	c := &BraiinsOS{
		Helper: request.NewHelper(log),
		embed: &embed{
			Icon_:     "generic",
			Features_: []api.Feature{api.IntegratedDevice},
		},
		log:      log,
		uri:      uri,
		user:     user,
		password: password,
		config: PowerControlConfig{
			MaxPower:          maxPower,
			Voltage:           voltage,
			PowerTargetStep:   powerTargetStep,
			DailyResetEnabled: dailyReset,
		},
		hardware: HardwareCapabilities{
			Name: "unknown",
		},
		intelligentDecrease: IntelligentDecreaseController{
			Enabled:              intelligentDecrease,
			MinDecreaseDuration:  minDecreaseDuration,
			DecreaseStepInterval: decreaseStepInterval,
			ConsistencyChecks:    defaultConsistencyChecks,
			RequestIndex:         0,
			RequestCount:         0,
		},
	}

	c.Client.Timeout = timeout
	c.hardware.Name = c.determineMinerName()

	if err := c.initialize(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *BraiinsOS) initialize() error {
	if err := c.login(); err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	if err := c.discoverConstraints(); err != nil {
		return fmt.Errorf("failed to get miner constraints: %w", err)
	}
	if err := c.discoverMinerStatus(); err != nil {
		return fmt.Errorf("failed to get miner status: %w", err)
	}
	if err := c.validateConfiguration(); err != nil {
		return err
	}
	c.displayConfigurationSummary()
	return nil
}

func (c *BraiinsOS) validateConfiguration() error {
	if c.config.MaxPower > 0 && c.config.MaxPower < c.hardware.MinWatts {
		return fmt.Errorf("configured maxPower (%dW) below hardware minimum (%dW)",
			c.config.MaxPower, c.hardware.MinWatts)
	}
	effectiveMax := c.getEffectiveMaxPower()
	if effectiveMax <= c.hardware.MinWatts {
		c.log.WARN.Printf("%s: Effective max power (%dW) too low - using minimum (%dW)",
			c.hardware.Name, effectiveMax, c.hardware.MinWatts)
		if err := c.setPowerTarget(c.hardware.MinWatts); err != nil {
			return err
		}
		return c.Enable(true)
	}
	return nil
}

func (c *BraiinsOS) determineMinerName() string {
	parsed, err := url.Parse(c.uri)
	if err != nil {
		return "unknown"
	}
	host := parsed.Host
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}
	if host != "" {
		return host
	}
	return "unknown"
}

func (c *BraiinsOS) tryGetHostname() string {
	resp, err := c.authRequest(http.MethodGet, apiPathNetworkConfig, nil)
	if err != nil {
		c.log.DEBUG.Printf("Network configuration request failed: %v", err)
		return ""
	}
	defer c.closeResponseBody(resp)
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var config NetworkConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return ""
	}
	return strings.TrimSuffix(config.Hostname, ".local")
}

func (c *BraiinsOS) tryUpdateHostname() {
	hostname := c.tryGetHostname()
	if hostname == "" || hostname == c.hardware.Name {
		return
	}
	c.mu.Lock()
	c.hardware.Name = hostname
	c.mu.Unlock()
}

func (c *BraiinsOS) displayConfigurationSummary() {
	effectiveMax := c.getEffectiveMaxPower()
	c.log.INFO.Printf("%s: Hardware: %dW (min) - %dW (default) - %dW (max)",
		c.hardware.Name, c.hardware.MinWatts, c.hardware.DefaultWatts, c.hardware.MaxWatts)
	if c.powerState.Enabled {
		c.logPowerTargetConfiguration(effectiveMax)
	} else {
		c.logOnOffConfiguration()
	}
}

func (c *BraiinsOS) logPowerTargetConfiguration(effectiveMax int) {
	currentTarget := c.hardware.DefaultWatts
	if c.powerState.LastTarget > 0 {
		currentTarget = c.powerState.LastTarget
	}
	c.log.INFO.Printf("%s: PowerTarget ENABLED - current: %dW", c.hardware.Name, currentTarget)
	c.logDPSStatus()
	c.logMaxPowerSource(effectiveMax)
	c.logIntelligentDecreaseStatus()
}

func (c *BraiinsOS) logDPSStatus() {
	if c.dps.Active {
		c.log.INFO.Printf("%s: DPS ACTIVE - cooperating with %dW steps",
			c.hardware.Name, c.dps.ActiveStep)
	} else if c.dps.Detected {
		c.log.INFO.Printf("%s: DPS detected but INACTIVE - evcc has full control", c.hardware.Name)
	}
}

func (c *BraiinsOS) logMaxPowerSource(effectiveMax int) {
	maxLabel := "Default"
	if c.config.MaxPower > 0 {
		maxLabel = "User-Setting"
	}
	resetInfo := ""
	if c.config.DailyResetEnabled {
		resetInfo = ", daily reset: enabled"
	}
	c.log.INFO.Printf("%s: evcc configuration: %dW - %dW (%s), %.0fV, step: %dW%s",
		c.hardware.Name, c.hardware.MinWatts, effectiveMax, maxLabel,
		c.config.Voltage, c.config.PowerTargetStep, resetInfo)
}

func (c *BraiinsOS) logIntelligentDecreaseStatus() {
	if c.intelligentDecrease.Enabled {
		c.log.INFO.Printf("%s: Intelligent decrease: ENABLED - wait: %v, step interval: %v",
			c.hardware.Name, c.intelligentDecrease.MinDecreaseDuration,
			c.intelligentDecrease.DecreaseStepInterval)
	} else {
		c.log.INFO.Printf("%s: Intelligent decrease: DISABLED - immediate response", c.hardware.Name)
	}
}

func (c *BraiinsOS) logOnOffConfiguration() {
	c.log.INFO.Printf("%s: PowerTarget DISABLED - on/off control only", c.hardware.Name)
	if c.dps.Active {
		c.log.INFO.Printf("%s: DPS ACTIVE", c.hardware.Name)
	}
	resetInfo := ""
	if c.config.DailyResetEnabled {
		resetInfo = ", daily reset: enabled"
	}
	c.log.INFO.Printf("%s: evcc configuration: %.0fV%s", c.hardware.Name, c.config.Voltage, resetInfo)
}

func (c *BraiinsOS) login() error {
	c.mu.Lock()
	if time.Now().Before(c.auth.TokenExpiry) && c.auth.Token != "" {
		c.mu.Unlock()
		return nil
	}

	loginReq := LoginRequest{
		Username: c.user,
		Password: c.password,
	}

	req, err := request.New(http.MethodPost, c.uri+apiPathLogin, request.MarshalJSON(loginReq), request.JSONEncoding)
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("failed to create login request: %w", err)
	}

	var resp LoginResponse
	if err := c.DoJSON(req, &resp); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("login request failed: %w", err)
	}

	if resp.Token == "" {
		c.mu.Unlock()
		return fmt.Errorf("no token received")
	}

	c.updateAuthToken(resp)
	c.mu.Unlock()

	c.tryUpdateHostname()
	c.log.DEBUG.Printf("%s: Login successful, token expires in %s",
		c.hardware.Name, time.Duration(resp.TimeoutS)*time.Second)

	return nil
}

func (c *BraiinsOS) updateAuthToken(resp LoginResponse) {
	c.auth.Token = resp.Token
	tokenTimeout := time.Duration(resp.TimeoutS) * time.Second
	if tokenTimeout <= 0 {
		tokenTimeout = defaultTokenTimeout
	}
	if tokenTimeout > tokenExpiryBufferSeconds*time.Second {
		c.auth.TokenExpiry = time.Now().Add(tokenTimeout - tokenExpiryBufferSeconds*time.Second)
	} else {
		c.auth.TokenExpiry = time.Now().Add(tokenTimeout)
	}
}

func (c *BraiinsOS) authRequest(method, path string, body any) (*http.Response, error) {
	for range 2 {
		resp, err := c.performAuthRequest(method, path, body)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized {
			c.handleUnauthorized(resp)
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("authentication failed after retry")
}

func (c *BraiinsOS) performAuthRequest(method, path string, body any) (*http.Response, error) {
	if err := c.login(); err != nil {
		return nil, err
	}
	req, err := c.createAuthenticatedRequest(method, path, body)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *BraiinsOS) createAuthenticatedRequest(method, path string, body any) (*http.Request, error) {
	var req *http.Request
	var err error
	if body != nil {
		req, err = request.New(method, c.uri+path, request.MarshalJSON(body), request.JSONEncoding)
	} else {
		req, err = request.New(method, c.uri+path, nil, request.JSONEncoding)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticated request: %w", err)
	}
	c.mu.Lock()
	token := c.auth.Token
	c.mu.Unlock()
	if token == "" {
		return nil, fmt.Errorf("no token available after login")
	}
	req.Header.Set("Authorization", token)
	return req, nil
}

func (c *BraiinsOS) handleUnauthorized(resp *http.Response) {
	c.log.WARN.Printf("%s: Token invalid (401), attempting re-authentication", c.hardware.Name)
	c.closeResponseBody(resp)
	c.mu.Lock()
	c.auth.Token = ""
	c.auth.TokenExpiry = time.Time{}
	c.mu.Unlock()
}

func (c *BraiinsOS) handleHTTPResponse(resp *http.Response, operation string) error {
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed after retry: %s (HTTP %d)", resp.Status, resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s failed: %s (HTTP %d)", operation, resp.Status, resp.StatusCode)
	}
	return nil
}

func (c *BraiinsOS) closeResponseBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
}

func (c *BraiinsOS) discoverConstraints() error {
	resp, err := c.authRequest(http.MethodGet, apiPathConstraints, nil)
	if err != nil {
		return fmt.Errorf("constraints request failed: %w", err)
	}
	defer c.closeResponseBody(resp)
	if err := c.handleHTTPResponse(resp, "constraints request"); err != nil {
		return err
	}
	var constraints ConfigConstraints
	if err := json.NewDecoder(resp.Body).Decode(&constraints); err != nil {
		return fmt.Errorf("failed to decode constraints: %w", err)
	}
	c.updateHardwareCapabilities(constraints)
	return nil
}

func (c *BraiinsOS) updateHardwareCapabilities(constraints ConfigConstraints) {
	c.hardware.MinWatts = constraints.TunerConstraints.PowerTarget.Min.Watt
	c.hardware.DefaultWatts = constraints.TunerConstraints.PowerTarget.Default.Watt
	c.hardware.MaxWatts = constraints.TunerConstraints.PowerTarget.Max.Watt
	dpsStep := constraints.DPSConstraints.PowerStep.Default.Watt
	dpsMinTarget := constraints.DPSConstraints.MinPowerTarget.Default.Watt
	c.dps.Detected = dpsStep > 0 && dpsMinTarget > 0
	if c.dps.Detected {
		c.dps.MinTarget = dpsMinTarget
		c.log.DEBUG.Printf("%s: DPS hardware detected: %dW, %dW",
			c.hardware.Name, dpsMinTarget, dpsStep)
	}
}

func (c *BraiinsOS) discoverMinerStatus() error {
	resp, err := c.authRequest(http.MethodGet, apiPathMinerConfig, nil)
	if err != nil {
		return fmt.Errorf("miner config request failed: %w", err)
	}
	defer c.closeResponseBody(resp)
	if err := c.handleHTTPResponse(resp, "miner config request"); err != nil {
		return err
	}
	var config MinerConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return fmt.Errorf("failed to decode miner config: %w", err)
	}
	c.updatePowerTargetState(config)
	c.updateDPSState(config)
	return nil
}

func (c *BraiinsOS) updatePowerTargetState(config MinerConfiguration) {
	c.powerState.Enabled = config.Tuner.Enabled && c.hardware.MaxWatts > 0
	if c.powerState.Enabled {
		currentTarget := c.hardware.DefaultWatts
		if config.Tuner.PowerTarget != nil {
			currentTarget = config.Tuner.PowerTarget.Watt
			c.powerState.LastTarget = currentTarget
			c.powerState.IsFromDiscovery = true
		}
		c.log.DEBUG.Printf("%s: PowerTarget detected: %dW", c.hardware.Name, currentTarget)
	}
}

func (c *BraiinsOS) updateDPSState(config MinerConfiguration) {
	c.dps.Active = config.DPS.Enabled
	c.dps.ActiveStep = config.DPS.PowerStep.Watt
	if c.dps.Active && c.dps.ActiveStep <= 0 {
		c.dps.ActiveStep = c.config.PowerTargetStep
		c.log.DEBUG.Printf("%s: DPS step not configured, using default: %dW",
			c.hardware.Name, c.config.PowerTargetStep)
	}
	if c.dps.Detected && c.dps.Active {
		c.log.DEBUG.Printf("%s: DPS configuration: min=%dW, step=%dW",
			c.hardware.Name, c.dps.MinTarget, c.dps.ActiveStep)
	}
}

func (c *BraiinsOS) getEffectiveMaxPower() int {
	effectiveMax := c.hardware.DefaultWatts
	if c.config.MaxPower > 0 {
		effectiveMax = c.config.MaxPower
	}
	if effectiveMax > c.hardware.MaxWatts {
		effectiveMax = c.hardware.MaxWatts
	}
	effectiveMin := c.getEffectiveMinWatts()
	if effectiveMax < effectiveMin {
		effectiveMax = effectiveMin
	}
	return effectiveMax
}

func (c *BraiinsOS) getEffectiveMinWatts() int {
	minWatts := c.hardware.MinWatts
	if c.dps.Active && c.dps.MinTarget > 0 {
		minWatts = c.dps.MinTarget
	}
	return minWatts
}

func (c *BraiinsOS) getMinCurrent() float64 {
	voltage := c.config.Voltage
	if voltage <= 0 {
		c.log.WARN.Printf("%s: Invalid voltage %.2f, using 230V default",
			c.hardware.Name, c.config.Voltage)
		voltage = defaultVoltage
	}
	minWatts := c.getEffectiveMinWatts()
	return float64(minWatts) / voltage
}

func (c *BraiinsOS) calculateTargetPower(powerRequest float64, isIncreasing bool) int {
	minLimit := c.getEffectiveMinWatts()
	effectiveMax := c.getEffectiveMaxPower()
	stepSize := c.config.PowerTargetStep
	if c.dps.Active && c.dps.ActiveStep > 0 {
		stepSize = c.dps.ActiveStep
	}
	if stepSize <= 0 || stepSize >= effectiveMax {
		c.log.WARN.Printf("%s: Invalid stepSize %d (min=%d, max=%d), using default %d",
			c.hardware.Name, stepSize, minLimit, effectiveMax, defaultPowerTargetStep)
		stepSize = defaultPowerTargetStep
	}
	limitedPower := math.Max(float64(minLimit), powerRequest)
	limitedPower = math.Min(float64(effectiveMax), limitedPower)
	var targetPower int
	if c.dps.Active {
		requestInt := int(math.Round(limitedPower))
		if requestInt <= minLimit {
			return minLimit
		}
		stepsFromMin := (requestInt - minLimit + stepSize/2) / stepSize
		targetPower = minLimit + stepsFromMin*stepSize
	} else {
		var steps int
		if isIncreasing {
			steps = int(math.Ceil(limitedPower / float64(stepSize)))
		} else {
			steps = int(math.Round(limitedPower / float64(stepSize)))
		}
		targetPower = steps * stepSize
	}
	targetPower = max(minLimit, min(targetPower, effectiveMax))
	return targetPower
}

func (c *BraiinsOS) getMinerStatus() (int, error) {
	resp, err := c.authRequest(http.MethodGet, apiPathMinerDetails, nil)
	if err != nil {
		return 0, fmt.Errorf("miner details request failed: %w", err)
	}
	defer c.closeResponseBody(resp)
	if err := c.handleHTTPResponse(resp, "miner details"); err != nil {
		return 0, err
	}
	var details MinerDetails
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		return 0, fmt.Errorf("failed to decode miner details: %w", err)
	}
	return details.Status, nil
}

func (c *BraiinsOS) setPowerTarget(targetWatts int) error {
	c.log.INFO.Printf("%s: Setting power target to %dW", c.hardware.Name, targetWatts)
	resp, err := c.authRequest(http.MethodPut, apiPathPowerTarget, PowerTarget{Watt: targetWatts})
	if err != nil {
		return fmt.Errorf("set power target failed: %w", err)
	}
	defer c.closeResponseBody(resp)
	if err := c.handlePowerTargetResponse(resp); err != nil {
		return err
	}
	c.mu.Lock()
	c.powerState.LastTarget = targetWatts
	c.powerState.LastUpdate = time.Now()
	c.powerState.IsFromDiscovery = false
	c.mu.Unlock()
	c.log.INFO.Printf("%s: Power target set successfully: %dW", c.hardware.Name, targetWatts)
	return nil
}

func (c *BraiinsOS) handlePowerTargetResponse(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusForbidden:
		c.log.DEBUG.Printf("%s: Power target temporarily deferred - DPS is actively regulating", c.hardware.Name)
		return nil
	case http.StatusConflict:
		c.log.DEBUG.Printf("%s: Power target deferred - DPS transition in progress", c.hardware.Name)
		return nil
	}
	return c.handleHTTPResponse(resp, "set power target")
}

// shouldActuallyDecrease determines if we should decrease and returns the power to decrease TO
func (c *BraiinsOS) shouldActuallyDecrease(requestedPower float64) (bool, float64) {
	if !c.intelligentDecrease.Enabled {
		return true, requestedPower
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.trackPowerRequest(requestedPower)

	currentTarget := c.powerState.LastTarget
	threshold := float64(currentTarget) * lowPowerThreshold

	effectiveMin := c.getEffectiveMinWatts()
	if currentTarget <= effectiveMin {
		if c.lp != nil {
			mode := c.lp.GetMode()

			if mode == api.ModeMinPV {
				return false, float64(currentTarget)
			}
		}

		threshold = float64(effectiveMin)
	}

	isLow := requestedPower < threshold

	if isLow {
		shouldDecrease, power := c.evaluateLowPowerCondition(currentTarget)
		return shouldDecrease, power
	}

	result := c.handlePowerRecovery()
	return result, float64(currentTarget)
}

func (c *BraiinsOS) trackPowerRequest(requestedPower float64) {
	now := time.Now()
	c.intelligentDecrease.RecentRequests[c.intelligentDecrease.RequestIndex] = requestedPower
	c.intelligentDecrease.RecentRequestTimes[c.intelligentDecrease.RequestIndex] = now
	c.intelligentDecrease.RequestIndex = (c.intelligentDecrease.RequestIndex + 1) % defaultRecentRequestsLimit
	if c.intelligentDecrease.RequestCount < defaultRecentRequestsLimit {
		c.intelligentDecrease.RequestCount++
	}
}

func (c *BraiinsOS) evaluateLowPowerCondition(currentTarget int) (bool, float64) {
	now := time.Now()
	if !c.intelligentDecrease.LowPowerStart.IsZero() {
		lowDuration := now.Sub(c.intelligentDecrease.LowPowerStart)
		if lowDuration > time.Hour {
			c.log.INFO.Printf("%s: Timer stale (%v old), restarting wait timer",
				c.hardware.Name, lowDuration.Round(time.Minute))
			c.intelligentDecrease.LowPowerStart = now
		}
	}

	if c.intelligentDecrease.LowPowerStart.IsZero() {
		c.intelligentDecrease.LowPowerStart = now
		c.intelligentDecrease.LastTimer1LoggedMinute = 0
		c.log.INFO.Printf("%s: Insufficient solar detected - starting %v wait timer (miner continues at current power)",
			c.hardware.Name, c.intelligentDecrease.MinDecreaseDuration)
	}

	lowDuration := now.Sub(c.intelligentDecrease.LowPowerStart)

	if lowDuration < c.intelligentDecrease.MinDecreaseDuration {
		remaining := c.intelligentDecrease.MinDecreaseDuration - lowDuration
		c.log.INFO.Printf("%s: Wait timer: %v elapsed, %v remaining (miner maintaining current power)",
			c.hardware.Name, lowDuration.Round(time.Second), remaining.Round(time.Second))
		return false, float64(currentTarget)
	}

	if !c.hasConsistentLowPower(currentTarget) {
		return false, float64(currentTarget)
	}

	avgPower := c.calculateAveragePower()
	return true, avgPower
}

func (c *BraiinsOS) hasConsistentLowPower(currentTarget int) bool {
	requiredSamples := c.intelligentDecrease.ConsistencyChecks
	if c.intelligentDecrease.RequestCount < requiredSamples {
		c.log.DEBUG.Printf("%s: Not enough samples yet (%d/%d) - ignoring",
			c.hardware.Name, c.intelligentDecrease.RequestCount, requiredSamples)
		return false
	}

	lowCount := 0
	threshold := float64(currentTarget) * lowPowerThreshold
	c.log.DEBUG.Printf("%s: Consistency check: need %d/%d samples below %.0fW (%.0f%% of %dW)",
		c.hardware.Name, int(float64(requiredSamples)*requiredConsistencyRatio), requiredSamples,
		threshold, lowPowerThreshold*100, currentTarget)

	var samples []float64
	for i := range requiredSamples {
		idx := (c.intelligentDecrease.RequestIndex - 1 - i + defaultRecentRequestsLimit) % defaultRecentRequestsLimit
		sample := c.intelligentDecrease.RecentRequests[idx]
		samples = append(samples, sample)
		if sample < threshold {
			lowCount++
		}
	}

	c.log.DEBUG.Printf("%s: Recent samples: %v (lowCount=%d/%d)",
		c.hardware.Name, samples, lowCount, requiredSamples)

	requiredLow := int(float64(requiredSamples) * requiredConsistencyRatio)
	if lowCount < requiredLow {
		c.log.DEBUG.Printf("%s: Only %d/%d checks low (need %d) - ignoring",
			c.hardware.Name, lowCount, requiredSamples, requiredLow)
		return false
	}

	return true
}

func (c *BraiinsOS) calculateAveragePower() float64 {
	requiredSamples := c.intelligentDecrease.ConsistencyChecks
	sum := 0.0
	for i := range requiredSamples {
		idx := (c.intelligentDecrease.RequestIndex - 1 - i + defaultRecentRequestsLimit) % defaultRecentRequestsLimit
		sum += c.intelligentDecrease.RecentRequests[idx]
	}
	return sum / float64(requiredSamples)
}

func (c *BraiinsOS) handlePowerRecovery() bool {
	if !c.intelligentDecrease.LowPowerStart.IsZero() {
		c.log.INFO.Printf("%s: Solar power recovered - resetting timers", c.hardware.Name)
		c.intelligentDecrease.LowPowerStart = time.Time{}
		c.intelligentDecrease.LastDecreaseStep = time.Time{}
	}

	return false
}

func (c *BraiinsOS) handlePowerDecrease(originalRequest float64, currentTarget int, wasClipped bool) (int, error) {
	shouldDecrease, decreasePower := c.shouldActuallyDecrease(originalRequest)

	if !shouldDecrease {
		return currentTarget, nil
	}

	newTarget := c.calculateDecreasedTarget(decreasePower, currentTarget, wasClipped)

	if newTarget == currentTarget {
		return currentTarget, nil
	}

	c.logDecreaseStep(newTarget, currentTarget)
	return newTarget, nil
}

func (c *BraiinsOS) calculateDecreasedTarget(decreasePower float64, currentTarget int, wasClipped bool) int {
	var newTarget int
	c.mu.Lock()

	now := time.Now()
	timeSinceLastStep := time.Since(c.intelligentDecrease.LastDecreaseStep)

	if !c.intelligentDecrease.LastDecreaseStep.IsZero() &&
		timeSinceLastStep < c.intelligentDecrease.DecreaseStepInterval {
		elapsedMinutes := int(timeSinceLastStep.Minutes())
		if elapsedMinutes > c.intelligentDecrease.LastTimer2LoggedMinute {
			c.intelligentDecrease.LastTimer2LoggedMinute = elapsedMinutes
			remaining := c.intelligentDecrease.DecreaseStepInterval - timeSinceLastStep
			c.log.INFO.Printf("%s: Step timer: %v elapsed, %v remaining before next decrease step",
				c.hardware.Name, timeSinceLastStep.Round(time.Minute), remaining.Round(time.Minute))
		}

		c.mu.Unlock()
		return currentTarget
	}

	stepSize := c.config.PowerTargetStep
	if c.dps.Active && c.dps.ActiveStep > 0 {
		stepSize = c.dps.ActiveStep
	}

	// CRITICAL FIX v0.4.35: Calculate DPS-aligned decreased target
	candidatePower := decreasePower - float64(stepSize)
	c.mu.Unlock() // Unlock before calling calculateTargetPower (it doesn't use mutex)

	candidate := c.calculateTargetPower(candidatePower, false)

	c.mu.Lock() // Re-lock for the rest of the function

	if candidate <= 0 {
		newTarget = 0
	} else {
		minTarget := c.getEffectiveMinWatts()

		if candidate < minTarget {
			if wasClipped {
				newTarget = 0
			} else if currentTarget <= minTarget+stepSize {
				c.log.INFO.Printf("%s: Near minimum power (%dW), shutting down to avoid hanging at minimum",
					c.hardware.Name, currentTarget)
				newTarget = 0
			} else {
				newTarget = minTarget
			}
		} else {
			newTarget = candidate
		}
	}

	c.intelligentDecrease.LastDecreaseStep = now
	c.intelligentDecrease.LastTimer2LoggedMinute = 0

	c.mu.Unlock()

	return newTarget
}

func (c *BraiinsOS) logDecreaseStep(newTarget, currentTarget int) {
	decreaseAmount := currentTarget - newTarget
	c.log.INFO.Printf("%s: Decreasing power: %dW → %dW (-%dW step)",
		c.hardware.Name, currentTarget, newTarget, decreaseAmount)
}

func (c *BraiinsOS) resetDecreaseTracking() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.intelligentDecrease.LowPowerStart.IsZero() {
		c.intelligentDecrease.LowPowerStart = time.Time{}
		c.intelligentDecrease.LastDecreaseStep = time.Time{}
		c.intelligentDecrease.LoggedFirstExpiry = false
		c.log.DEBUG.Printf("%s: Intelligent decrease timers reset", c.hardware.Name)
	}
}

func (c *BraiinsOS) checkDailyReset() api.ChargeStatus {
	if !c.config.DailyResetEnabled {
		return api.StatusNone
	}
	now := time.Now()
	if now.Hour() == dailyResetHour && now.Minute() == dailyResetMinute {
		c.mu.Lock()
		if !c.session.DailyResetDone {
			c.session.DailyResetDone = true
			c.mu.Unlock()
			c.log.INFO.Printf("%s: Daily session reset triggered at 23:59", c.hardware.Name)
			return api.StatusA
		}
		c.mu.Unlock()
	} else if now.Hour() != dailyResetHour || now.Minute() != dailyResetMinute {
		c.mu.Lock()
		c.session.DailyResetDone = false
		c.mu.Unlock()
	}
	return api.StatusNone
}

func (c *BraiinsOS) CurrentPower() (float64, error) {
	c.mu.Lock()
	isPausing := c.powerState.IsPausing
	pauseStarted := c.powerState.PauseStarted
	c.mu.Unlock()

	if isPausing && !pauseStarted.IsZero() && time.Since(pauseStarted) < 60*time.Second {
		elapsed := time.Since(pauseStarted).Round(time.Second)
		c.log.DEBUG.Printf("%s: Miner in pause grace period (%v elapsed), returning 0W to avoid stale reading",
			c.hardware.Name, elapsed)
		return 0, nil
	}

	resp, err := c.authRequest(http.MethodGet, apiPathMinerStats, nil)
	if err != nil {
		return 0, fmt.Errorf("stats request failed: %w", err)
	}
	defer c.closeResponseBody(resp)

	if err := c.handleHTTPResponse(resp, "stats"); err != nil {
		return 0, err
	}

	var stats MinerStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return 0, fmt.Errorf("failed to decode miner stats: %w", err)
	}

	power := float64(stats.PowerStats.ApproximatedConsumption.Watt)
	return power, nil
}

func (c *BraiinsOS) Currents() (float64, float64, float64, error) {
	power, err := c.CurrentPower()
	if err != nil {
		return 0, 0, 0, err
	}
	if c.config.Voltage <= 0 {
		return 0, 0, 0, fmt.Errorf("invalid voltage: %.2f", c.config.Voltage)
	}
	current := power / c.config.Voltage
	return current, 0, 0, nil
}

func (c *BraiinsOS) handleModeSpecificBehavior() {
	mode := c.lp.GetMode()
	c.mu.Lock()
	c.currentMode = mode
	c.mu.Unlock()

	switch mode {
	case api.ModeMinPV:
		c.mu.Lock()
		if !c.intelligentDecrease.LowPowerStart.IsZero() {
			c.log.DEBUG.Printf("%s: MinPV mode (target: %dW) - resetting any running decrease timer",
				c.hardware.Name, c.powerState.LastTarget)
			c.intelligentDecrease.LowPowerStart = time.Time{}
		}
		c.mu.Unlock()

	case api.ModePV:
		effectiveMin := c.getEffectiveMinWatts()
		atMinimum := c.powerState.LastTarget <= effectiveMin && c.powerState.LastTarget > 0

		if atMinimum {
			enabled, err := c.Enabled()
			if err != nil || !enabled {
				c.mu.Lock()
				if !c.intelligentDecrease.LowPowerStart.IsZero() {
					c.intelligentDecrease.LowPowerStart = time.Time{}
					c.log.DEBUG.Printf("%s: PV mode - miner OFF, clearing decrease timer", c.hardware.Name)
				}
				c.mu.Unlock()
				return
			}

			c.mu.Lock()
			if c.intelligentDecrease.LowPowerStart.IsZero() {
				c.log.INFO.Printf("%s: PV mode (target: %dW) - running at minimum with insufficient PV - starting 15min decrease timer",
					c.hardware.Name, c.powerState.LastTarget)
				c.intelligentDecrease.LowPowerStart = time.Now()
				c.intelligentDecrease.LastTimer1LoggedMinute = 0
			}
			c.mu.Unlock()
		}

		c.mu.Lock()
		if !c.intelligentDecrease.LowPowerStart.IsZero() {
			elapsed := time.Since(c.intelligentDecrease.LowPowerStart)
			c.mu.Unlock()

			if elapsed >= c.intelligentDecrease.MinDecreaseDuration {
				if !c.intelligentDecrease.LoggedFirstExpiry {
					c.log.INFO.Printf("%s: Decrease timer elapsed (%v) - starting stepped shutdown",
						c.hardware.Name, elapsed.Round(time.Second))
					c.intelligentDecrease.LoggedFirstExpiry = true
				}
				c.performSteppedShutdown()
			} else {
				elapsedMinutes := int(elapsed.Minutes())
				if elapsedMinutes > c.intelligentDecrease.LastTimer1LoggedMinute {
					c.intelligentDecrease.LastTimer1LoggedMinute = elapsedMinutes
					remaining := c.intelligentDecrease.MinDecreaseDuration - elapsed
					c.log.DEBUG.Printf("%s: PV mode (target: %dW) - decrease timer: %v elapsed, %v remaining",
						c.hardware.Name, c.powerState.LastTarget,
						elapsed.Round(time.Minute), remaining.Round(time.Minute))
				}
			}
		} else {
			c.mu.Unlock()
		}

	case api.ModeNow:
		c.mu.Lock()
		if !c.intelligentDecrease.LowPowerStart.IsZero() {
			c.log.DEBUG.Printf("%s: Now mode (target: %dW) - full charge requested, resetting decrease timer",
				c.hardware.Name, c.powerState.LastTarget)
			c.intelligentDecrease.LowPowerStart = time.Time{}
		}
		c.mu.Unlock()

	case api.ModeOff:
		c.mu.Lock()
		if !c.intelligentDecrease.LowPowerStart.IsZero() {
			c.log.DEBUG.Printf("%s: Off mode - resetting decrease timer",
				c.hardware.Name)
			c.intelligentDecrease.LowPowerStart = time.Time{}
		}
		c.mu.Unlock()
	}
}

func (c *BraiinsOS) performSteppedShutdown() {
	var action int
	var target int

	c.mu.Lock()

	now := time.Now()

	if !c.intelligentDecrease.LastDecreaseStep.IsZero() {
		timeSinceLastStep := time.Since(c.intelligentDecrease.LastDecreaseStep)
		if timeSinceLastStep < c.intelligentDecrease.DecreaseStepInterval {
			c.mu.Unlock()
			return
		}
	}

	currentTarget := c.powerState.LastTarget

	effectiveMin := c.getEffectiveMinWatts()
	stepSize := c.config.PowerTargetStep
	if c.dps.Active && c.dps.ActiveStep > 0 {
		stepSize = c.dps.ActiveStep
	}

	nextTarget := currentTarget - stepSize

	if nextTarget <= effectiveMin {
		action = 2

		c.powerState.IsPausing = true
		c.powerState.PauseStarted = time.Now()

		c.powerState.PausedByTimer = true
		c.log.INFO.Printf("%s: Step-wise decrease reached minimum (%dW → disable) - shutting down miner",
			c.hardware.Name, currentTarget)
		c.log.INFO.Printf("%s: Miner paused by intelligent decrease timer - remains off until sufficient solar power returns",
			c.hardware.Name)
	} else {
		action = 1
		target = nextTarget

		c.powerState.LastTarget = nextTarget
		c.intelligentDecrease.LastDecreaseStep = now

		c.log.INFO.Printf("%s: Step-wise decrease: %dW → %dW (next step in %v)",
			c.hardware.Name, currentTarget, nextTarget, c.intelligentDecrease.DecreaseStepInterval)
	}

	c.mu.Unlock()

	switch action {
	case 1:
		err := c.setPowerTarget(target)
		if err != nil {
			c.log.ERROR.Printf("%s: Failed to set power target during stepped shutdown: %v", c.hardware.Name, err)
		}

	case 2:
		err := c.Enable(false)
		if err != nil {
			c.log.ERROR.Printf("%s: Failed to disable miner during stepped shutdown: %v", c.hardware.Name, err)
			return
		}

		c.mu.Lock()
		c.intelligentDecrease.LowPowerStart = time.Time{}
		c.intelligentDecrease.LastDecreaseStep = time.Time{}
		c.mu.Unlock()
	}
}

func (c *BraiinsOS) Status() (api.ChargeStatus, error) {
	if resetStatus := c.checkDailyReset(); resetStatus != api.StatusNone {
		return resetStatus, nil
	}

	c.mu.Lock()
	isPausing := c.powerState.IsPausing
	pausedByTimer := c.powerState.PausedByTimer
	c.mu.Unlock()

	if isPausing || pausedByTimer {
		c.log.DEBUG.Printf("%s: Grace period or paused by timer - returning StatusB",
			c.hardware.Name)
		return api.StatusB, nil
	}

	status, err := c.getMinerStatus()
	if err != nil {
		return api.StatusNone, err
	}

	if c.lp != nil {
		c.mu.Lock()
		c.currentMode = c.lp.GetMode()
		c.mu.Unlock()
	}

	if c.lp != nil {
		c.handleModeSpecificBehavior()
	}

	if c.lp != nil && c.lp.GetMode() == api.ModeOff {
		if status == MinerStatusMining || status == MinerStatusDegraded {
			c.log.DEBUG.Printf("%s: LoadpointController in ModeOff, but miner still active - using StatusB",
				c.hardware.Name)
			return api.StatusB, nil
		}
	}

	return c.mapMinerStatusToChargeStatus(status), nil
}

func (c *BraiinsOS) mapMinerStatusToChargeStatus(status int) api.ChargeStatus {
	switch status {
	case MinerStatusMining:
		return api.StatusC
	case MinerStatusPaused:
		return api.StatusB
	case MinerStatusIdle:
		return api.StatusB
	case MinerStatusDegraded:
		return api.StatusC
	case MinerStatusError:
		return api.StatusNone
	default:
		return api.StatusNone
	}
}

func (c *BraiinsOS) Enabled() (bool, error) {
	c.mu.Lock()
	isPausing := c.powerState.IsPausing
	pausedByTimer := c.powerState.PausedByTimer
	c.mu.Unlock()

	if isPausing || pausedByTimer {
		return false, nil
	}

	status, err := c.getMinerStatus()
	if err != nil {
		return false, err
	}
	return status == MinerStatusMining || status == MinerStatusDegraded, nil
}

func (c *BraiinsOS) Enable(enable bool) error {
	endpoint, operation := c.getEnableEndpoint(enable)

	if !enable {
		c.mu.Lock()
		if !c.powerState.IsPausing {
			c.powerState.IsPausing = true
			c.powerState.PauseStarted = time.Now()
			c.log.DEBUG.Printf("%s: Starting grace period", c.hardware.Name)
		} else {
			c.log.DEBUG.Printf("%s: Grace period already active - skipping redundant set", c.hardware.Name)
		}
		c.mu.Unlock()

		c.log.DEBUG.Printf("%s: Sending pause command", c.hardware.Name)
	} else {
		c.mu.Lock()
		pausedByTimer := c.powerState.PausedByTimer
		isInPVMode := c.currentMode == api.ModePV
		c.mu.Unlock()

		if pausedByTimer && isInPVMode {
			c.log.DEBUG.Printf("%s: Miner paused by intelligent decrease timer (PV mode) - NOT resuming despite evcc request",
				c.hardware.Name)
			return nil
		}

		if pausedByTimer && !isInPVMode {
			c.mu.Lock()
			c.powerState.PausedByTimer = false
			c.log.INFO.Printf("%s: Mode switched from PV to %s - clearing pausedByTimer, miner can resume",
				c.hardware.Name, c.currentMode)
			c.mu.Unlock()
		}

		c.mu.Lock()
		if c.powerState.IsPausing {
			c.powerState.IsPausing = false
			c.log.DEBUG.Printf("%s: Resume called during grace period - cancelling pause state", c.hardware.Name)
		}
		c.mu.Unlock()
	}

	resp, err := c.authRequest(http.MethodPut, endpoint, nil)
	if err != nil {
		if !enable {
			c.mu.Lock()
			c.powerState.IsPausing = false
			c.mu.Unlock()
		}
		return err
	}
	defer c.closeResponseBody(resp)

	if err := c.handleHTTPResponse(resp, operation); err != nil {
		if !enable {
			c.mu.Lock()
			c.powerState.IsPausing = false
			c.mu.Unlock()
		}
		return err
	}

	if !enable {
		c.resetDecreaseTracking()

		go func() {
			time.Sleep(60 * time.Second)
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.powerState.IsPausing {
				c.powerState.IsPausing = false
				c.log.DEBUG.Printf("%s: Grace period ended (60s), resuming normal power readings", c.hardware.Name)
			}
		}()
	}

	c.log.DEBUG.Printf("%s: Miner %s successful", c.hardware.Name, operation)
	return nil
}

func (c *BraiinsOS) getEnableEndpoint(enable bool) (string, string) {
	if enable {
		return apiPathResume, "resume"
	}
	return apiPathPause, "pause"
}

func (c *BraiinsOS) MaxCurrent(current int64) error {
	return c.MaxCurrentMillis(float64(current))
}

func (c *BraiinsOS) MaxCurrentMillis(current float64) error {
	c.log.DEBUG.Printf("%s: MaxCurrentMillis called: %.2fA (%.0fW)",
		c.hardware.Name, current, current*c.config.Voltage)

	if current < 0 {
		return fmt.Errorf("invalid negative current value: %.2f", current)
	}

	if current == 0 {
		c.log.DEBUG.Printf("%s: current=0 → calling Enable(false)", c.hardware.Name)
		return c.Enable(false)
	}

	originalPowerRequest := current * c.config.Voltage

	minCurrent := c.getMinCurrent()
	minPower := minCurrent * c.config.Voltage
	wasClipped := false
	if current < minCurrent {
		wasClipped = true
		c.log.DEBUG.Printf("%s: Request %.0fW below minimum %.0fW - clipping to minimum (timer tracks original)",
			c.hardware.Name, originalPowerRequest, minPower)
		current = minCurrent
	}

	clippedPowerRequest := current * c.config.Voltage

	var targetPowerInt int
	var powerChanged bool
	var doEnableFalse bool
	var doSetPower bool
	var decreaseHandled bool

	c.mu.Lock()
	currentTarget := c.powerState.LastTarget
	isFromDiscovery := c.powerState.IsFromDiscovery
	isInPVMode := c.currentMode == api.ModePV
	c.mu.Unlock()

	if originalPowerRequest < float64(currentTarget) && isInPVMode {
		c.mu.Lock()
		if c.intelligentDecrease.LowPowerStart.IsZero() {
			c.intelligentDecrease.LowPowerStart = time.Now()
		}
		c.mu.Unlock()

		newTargetInt, err := c.handlePowerDecrease(originalPowerRequest, currentTarget, wasClipped)
		if err != nil {
			return err
		}

		// CRITICAL FIX v0.4.35: Use the DPS-aligned result from handlePowerDecrease directly
		if newTargetInt == 0 {
			doEnableFalse = true
			c.mu.Lock()
			c.powerState.PausedByTimer = true
			c.log.INFO.Printf("%s: Miner paused due to insufficient solar power - remains off until sufficient power returns",
				c.hardware.Name)
			c.mu.Unlock()
		} else if newTargetInt != currentTarget {
			// handlePowerDecrease returned a new target - use it directly (already DPS-aligned)
			targetPowerInt = newTargetInt
			powerChanged = true
			decreaseHandled = true
			c.log.DEBUG.Printf("%s: Using DPS-aligned target from handlePowerDecrease: %dW",
				c.hardware.Name, targetPowerInt)
		} else {
			// No change from handlePowerDecrease - keep current target
			targetPowerInt = currentTarget
			powerChanged = false
			decreaseHandled = true
		}
	} else {
		c.resetDecreaseTracking()
	}

	if !c.powerState.Enabled {
		return c.handleOnOffControl()
	}

	// Only calculate target power if decrease was NOT handled
	if !decreaseHandled {
		powerRequest := clippedPowerRequest
		isIncreasing := powerRequest > float64(currentTarget)
		targetPowerInt = c.calculateTargetPower(powerRequest, isIncreasing)
		powerChanged = targetPowerInt != currentTarget
	}

	if isFromDiscovery {
		c.log.DEBUG.Printf("%s: First call after discovery (target: %dW) - forcing setPowerTarget()",
			c.hardware.Name, targetPowerInt)
		powerChanged = true
	}

	if !powerChanged {
		c.log.DEBUG.Printf("%s: Power unchanged at %dW (requested: %.0fW, original: %.0fW) → no action",
			c.hardware.Name, targetPowerInt, clippedPowerRequest, originalPowerRequest)
		return nil
	}

	doSetPower = true

	if doEnableFalse {
		c.log.INFO.Printf("%s: Insufficient solar power - turning off miner", c.hardware.Name)
		return c.Enable(false)
	}

	if doSetPower {
		if err := c.setPowerTarget(targetPowerInt); err != nil {
			return err
		}
	}

	if err := c.ensureMinerEnabled(); err != nil {
		return err
	}

	effectiveMin := c.getEffectiveMinWatts()
	if targetPowerInt > effectiveMin {
		c.mu.Lock()
		if c.powerState.PausedByTimer {
			c.powerState.PausedByTimer = false
			c.log.INFO.Printf("%s: Sufficient solar power returned and power set - clearing pausedByTimer flag (target: %dW > min: %dW)",
				c.hardware.Name, targetPowerInt, effectiveMin)
		}
		c.mu.Unlock()
	}

	return nil
}

func (c *BraiinsOS) handleOnOffControl() error {
	if !c.powerState.WarningShown {
		c.log.INFO.Printf("%s: Using on/off control (PowerTarget not available)", c.hardware.Name)
		c.powerState.WarningShown = true
	}
	enabled, err := c.Enabled()
	if err != nil {
		return err
	}
	if !enabled {
		return c.Enable(true)
	}
	return nil
}

func (c *BraiinsOS) ensureMinerEnabled() error {
	c.mu.Lock()
	isPausing := c.powerState.IsPausing
	pausedByTimer := c.powerState.PausedByTimer
	c.mu.Unlock()

	if pausedByTimer {
		c.log.DEBUG.Printf("%s: Miner paused by intelligent decrease timer - keeping off",
			c.hardware.Name)
		return nil
	}

	if isPausing {
		c.log.DEBUG.Printf("%s: Miner in pause grace period - skipping enable check", c.hardware.Name)
		return nil
	}

	enabled, err := c.Enabled()
	if err != nil {
		return err
	}

	if !enabled {
		return c.Enable(true)
	}

	return nil
}

func (c *BraiinsOS) LoadpointControl(lp loadpoint.API) {
	c.lp = lp
	c.currentMode = lp.GetMode()
	c.log.DEBUG.Printf("%s: LoadpointController interface connected (mode: %s)", c.hardware.Name, c.currentMode)
}

var _ api.Charger = (*BraiinsOS)(nil)
var _ api.ChargerEx = (*BraiinsOS)(nil)
var _ api.Meter = (*BraiinsOS)(nil)
var _ api.PhaseCurrents = (*BraiinsOS)(nil)
var _ loadpoint.Controller = (*BraiinsOS)(nil)
