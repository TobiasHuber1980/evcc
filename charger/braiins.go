// Native Go implementation for Braiins OS evcc integration
// https://developer.braiins-os.com/latest/openapi.html
// - For dynamic power control: Enable "Power Target" mode in Braiins OS tuner settings
// - Without Power Target: Only on/off control available
// - Also enable DPS-Mode if needed
// Version: 2.0.0 (Optimized hybrid version - best of 1.9.14+ and 1.9.21)
// - REMOVED: Daily session reset at 23:59 (problematic behavior)
// - OPTIMIZED: Selective logging strategy (operational info + debug capabilities)
// - ENHANCED: Network error handling with informative feedback
// - MAINTAINED: All power control logs for troubleshooting
// - IMPROVED: Silent cleanup with preserved debug info where needed

package charger

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/evcc-io/evcc/api"
	"github.com/evcc-io/evcc/util"
	"github.com/evcc-io/evcc/util/request"
)

const (
	MinerStatusUnspecified = 0
	MinerStatusIdle        = 1
	MinerStatusMining      = 2
	MinerStatusPaused      = 3
	MinerStatusDegraded    = 4
	MinerStatusError       = 5
)

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

type BraiinsOS struct {
	*request.Helper
	*embed
	uri            string
	user           string
	password       string
	configMaxPower int
	voltage        float64
	minerName      string

	powerTargetInterval time.Duration
	powerTargetStep     int

	minWatts     int
	defaultWatts int
	maxWatts     int

	powerTargetEnabled bool
	powerTargetWarned  bool

	dpsDetected   bool
	dpsActive     bool
	dpsMinTarget  int
	dpsActiveStep int

	mu              sync.Mutex
	token           string
	tokenExpiry     time.Time
	lastPowerUpdate time.Time
	lastPowerTarget int

	log *util.Logger
}

type BraiinsConfig struct {
	URI                 string        `mapstructure:"uri"`
	User                string        `mapstructure:"user"`
	Password            string        `mapstructure:"password"`
	Timeout             time.Duration `mapstructure:"timeout"`
	MaxPower            int           `mapstructure:"maxPower"`
	Voltage             float64       `mapstructure:"voltage"`
	PowerTargetInterval time.Duration `mapstructure:"powerTargetInterval"`
	PowerTargetStep     int           `mapstructure:"powerTargetStep"`
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
	Hostname string                 `json:"hostname"`
	Protocol map[string]interface{} `json:"protocol,omitempty"`
}

type MinerConfiguration struct {
	Dps struct {
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

	DpsConstraints struct {
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

// ensureScheme adds http:// if no scheme is present
func ensureScheme(u string) string {
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	return "http://" + u
}

// NewBraiinsFromConfig creates a Braiins charger from generic config
func NewBraiinsFromConfig(other map[string]interface{}) (api.Charger, error) {
	var cc BraiinsConfig
	if err := util.DecodeOther(other, &cc); err != nil {
		return nil, err
	}

	if cc.Timeout == 0 {
		cc.Timeout = 15 * time.Second
	}
	if cc.User == "" {
		cc.User = "root"
	}
	if cc.Voltage == 0 {
		cc.Voltage = 230.0
	}
	if cc.PowerTargetInterval == 0 {
		cc.PowerTargetInterval = 15 * time.Second
	}
	if cc.PowerTargetStep == 0 {
		cc.PowerTargetStep = 100
	}

	uri := ensureScheme(cc.URI)
	return NewBraiins(uri, cc.User, cc.Password, cc.Timeout, cc.MaxPower, cc.Voltage, cc.PowerTargetInterval, cc.PowerTargetStep)
}

// tryGetHostname attempts to discover hostname via network configuration API
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

// determineMinerName gets hostname from API, falls back to IP from URI
func (c *BraiinsOS) determineMinerName() string {
	if hostname := c.tryGetHostname(); hostname != "" {
		return hostname
	}

	if parsed, err := url.Parse(c.uri); err == nil {
		host := parsed.Host
		if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
			host = host[:colonIndex]
		}
		return host
	}

	return "unknown"
}

// NewBraiins creates a new Braiins charger instance
func NewBraiins(uri, user, password string, timeout time.Duration, maxPower int, voltage float64, powerTargetInterval time.Duration, powerTargetStep int) (api.Charger, error) {
	log := util.NewLogger("braiins")

	c := &BraiinsOS{
		Helper: request.NewHelper(log),
		embed: &embed{
			Icon_:     "generic",
			Features_: []api.Feature{api.IntegratedDevice},
		},
		log:                 log,
		uri:                 uri,
		user:                user,
		password:            password,
		configMaxPower:      maxPower,
		voltage:             voltage,
		powerTargetInterval: powerTargetInterval,
		powerTargetStep:     powerTargetStep,
		minerName:           "unknown",
	}

	c.Client.Timeout = timeout

	// Determine miner name before login to avoid "unknown" in logs
	c.minerName = c.determineMinerName()

	if err := c.login(); err != nil {
		return nil, fmt.Errorf("connection test failed: %w", err)
	}

	if err := c.discoverConstraints(); err != nil {
		return nil, fmt.Errorf("failed to get miner constraints: %w", err)
	}

	if err := c.discoverMinerStatus(); err != nil {
		return nil, fmt.Errorf("failed to get miner status: %w", err)
	}

	if c.configMaxPower > 0 && c.configMaxPower < c.minWatts {
		return nil, fmt.Errorf("configured maxPower (%dW) below hardware minimum (%dW)", c.configMaxPower, c.minWatts)
	}

	effectiveMax := c.getEffectiveMaxPower()
	if effectiveMax <= c.minWatts {
		c.log.WARN.Printf("%s: Effective max power (%dW) too low - using minimum (%dW)",
			c.minerName, effectiveMax, c.minWatts)
		if err := c.setPowerTarget(c.minWatts); err != nil {
			return c, err
		}
		return c, c.Enable(true)
	}

	c.displayConfigurationSummary()
	return c, nil
}

// displayConfigurationSummary shows miner capabilities and control mode
func (c *BraiinsOS) displayConfigurationSummary() {
	effectiveMax := c.getEffectiveMaxPower()

	if c.powerTargetEnabled {
		var maxLabel string
		if c.configMaxPower > 0 {
			maxLabel = "User"
		} else {
			maxLabel = "Default"
		}

		var dpsInfo string
		if c.dpsActive {
			dpsInfo = fmt.Sprintf(", DPS: ACTIVE (step: %dW) - limited evcc control", c.dpsActiveStep)
		} else if c.dpsDetected {
			dpsInfo = ", DPS: available but inactive - full evcc control"
		} else {
			dpsInfo = ", DPS: not available"
		}

		c.log.INFO.Printf("%s: Power control ready - evcc: %dW (Min.) - %dW (%s), hardware: %dW-%dW-%dW, %.0fV, interval: %v, step: %dW%s",
			c.minerName, c.minWatts, effectiveMax, maxLabel, c.minWatts, c.defaultWatts, c.maxWatts, c.voltage, c.powerTargetInterval, c.powerTargetStep, dpsInfo)
	} else {
		c.log.INFO.Printf("%s: On/off control only (%.0fV)%s", c.minerName, c.voltage,
			func() string {
				if c.dpsActive {
					return ", DPS: active"
				}
				return ""
			}())
	}
}

// login gets a new authentication token with thread-safe token management
func (c *BraiinsOS) login() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Now().Before(c.tokenExpiry) && c.token != "" {
		return nil
	}

	loginReq := LoginRequest{
		Username: c.user,
		Password: c.password,
	}

	req, err := request.New(http.MethodPost, c.uri+apiPathLogin, request.MarshalJSON(loginReq), request.JSONEncoding)
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}

	var resp LoginResponse
	if err := c.DoJSON(req, &resp); err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}

	if resp.Token == "" {
		return fmt.Errorf("no token received")
	}

	c.token = resp.Token

	tokenTimeout := time.Duration(resp.TimeoutS) * time.Second
	if tokenTimeout <= 0 {
		tokenTimeout = 1 * time.Hour
	}
	if tokenTimeout > 30*time.Second {
		c.tokenExpiry = time.Now().Add(tokenTimeout - 30*time.Second)
	} else {
		c.tokenExpiry = time.Now().Add(tokenTimeout)
	}

	c.log.DEBUG.Printf("%s: Login successful, token expires in %s", c.minerName, tokenTimeout)
	return nil
}

// authRequest makes an authenticated HTTP request with automatic retry on 401
func (c *BraiinsOS) authRequest(method, path string, body any) (*http.Response, error) {
	doRequest := func() (*http.Response, error) {
		if err := c.login(); err != nil {
			return nil, err
		}

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
		token := c.token
		c.mu.Unlock()

		if token == "" {
			return nil, fmt.Errorf("no token available after login")
		}

		req.Header.Set("Authorization", token)
		return c.Do(req)
	}

	for retry := 0; retry < 2; retry++ {
		resp, err := doRequest()
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusUnauthorized {
			c.log.WARN.Printf("%s: Token invalid (401), attempting re-authentication", c.minerName)
			c.closeResponseBody(resp)
			c.mu.Lock()
			c.token = ""
			c.tokenExpiry = time.Time{}
			c.mu.Unlock()
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("authentication failed after retry")
}

// handleHTTPResponse checks status codes and provides consistent error handling
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

// closeResponseBody safely closes response body (silent cleanup)
func (c *BraiinsOS) closeResponseBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		if err := resp.Body.Close(); err != nil {
			// Silently ignore close errors in cleanup
		}
	}
}

// discoverConstraints gets miner power limits and detects DPS hardware support
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

	c.minWatts = constraints.TunerConstraints.PowerTarget.Min.Watt
	c.defaultWatts = constraints.TunerConstraints.PowerTarget.Default.Watt
	c.maxWatts = constraints.TunerConstraints.PowerTarget.Max.Watt

	dpsStep := constraints.DpsConstraints.PowerStep.Default.Watt
	dpsMinTarget := constraints.DpsConstraints.MinPowerTarget.Default.Watt
	c.dpsDetected = dpsStep > 0 && dpsMinTarget > 0

	if c.dpsDetected {
		c.dpsMinTarget = dpsMinTarget
		c.log.INFO.Printf("%s: DPS hardware detected: min=%dW, step=%dW", c.minerName, dpsMinTarget, dpsStep)
	}

	c.log.DEBUG.Printf("%s: Hardware constraints - min=%dW, default=%dW, max=%dW, dps=%v",
		c.minerName, c.minWatts, c.defaultWatts, c.maxWatts, c.dpsDetected)

	return nil
}

// discoverMinerStatus checks actual PowerTarget and DPS status from real configuration
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

	c.powerTargetEnabled = config.Tuner.Enabled && c.maxWatts > 0
	c.dpsActive = config.Dps.Enabled
	c.dpsActiveStep = config.Dps.PowerStep.Watt

	if c.powerTargetEnabled {
		currentTarget := "not set"
		if config.Tuner.PowerTarget != nil {
			currentTarget = fmt.Sprintf("%dW", config.Tuner.PowerTarget.Watt)
		} else {
			c.log.DEBUG.Printf("%s: PowerTarget is enabled but not explicitly set in config", c.minerName)
		}
		c.log.INFO.Printf("%s: PowerTarget ENABLED - current: %s, mode: %d",
			c.minerName, currentTarget, config.Tuner.TunerMode)
	} else {
		if !config.Tuner.Enabled {
			c.log.INFO.Printf("%s: PowerTarget DISABLED - tuner not enabled", c.minerName)
		} else if c.maxWatts <= 0 {
			c.log.INFO.Printf("%s: PowerTarget DISABLED - invalid hardware limits", c.minerName)
		}
	}

	if c.dpsDetected {
		if c.dpsActive {
			c.log.INFO.Printf("%s: DPS ACTIVE - evcc will cooperate with DPS control", c.minerName)
			c.log.INFO.Printf("%s: DPS configuration: step=%dW, mode=%d", c.minerName, c.dpsActiveStep, config.Dps.Mode)
		} else {
			c.log.INFO.Printf("%s: DPS available but INACTIVE - evcc has full control", c.minerName)
		}
	}

	return nil
}

// getEffectiveMaxPower returns the effective maximum power for evcc control
func (c *BraiinsOS) getEffectiveMaxPower() int {
	effectiveMax := c.defaultWatts
	if c.configMaxPower > 0 {
		effectiveMax = c.configMaxPower
	}

	if effectiveMax > c.maxWatts {
		effectiveMax = c.maxWatts
	}
	if effectiveMax < c.minWatts {
		effectiveMax = c.minWatts
	}

	return effectiveMax
}

// getMinerStatus gets the current miner status
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

// setPowerTarget sets the miner power target
func (c *BraiinsOS) setPowerTarget(targetWatts int) error {
	c.log.INFO.Printf("%s: Setting power target to %dW", c.minerName, targetWatts)

	resp, err := c.authRequest(http.MethodPut, apiPathPowerTarget, PowerTarget{Watt: targetWatts})
	if err != nil {
		return fmt.Errorf("set power target failed: %w", err)
	}
	defer c.closeResponseBody(resp)

	switch resp.StatusCode {
	case http.StatusForbidden:
		if resp.Body != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			if len(body) > 0 {
				c.log.DEBUG.Printf("%s: Error response body: %s", c.minerName, string(body))
			}
		}
		c.log.ERROR.Printf("%s: Power target BLOCKED (403) - DPS conflict detected", c.minerName)
		if c.dpsActive {
			c.log.ERROR.Printf("%s: DPS is active - disable DPS for full evcc control", c.minerName)
		}
		return fmt.Errorf("power target blocked by DPS (HTTP 403)")
	case http.StatusConflict:
		c.log.ERROR.Printf("%s: Power target CONFLICT (409) - DPS interference", c.minerName)
		return fmt.Errorf("power target conflict with DPS (HTTP 409)")
	}

	if err := c.handleHTTPResponse(resp, "set power target"); err != nil {
		return err
	}

	c.mu.Lock()
	c.lastPowerTarget = targetWatts
	c.lastPowerUpdate = time.Now()
	c.mu.Unlock()

	c.log.INFO.Printf("%s: Power target set successfully: %dW", c.minerName, targetWatts)
	return nil
}

// CurrentPower implements the api.Meter interface
func (c *BraiinsOS) CurrentPower() (float64, error) {
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
	c.log.DEBUG.Printf("%s: Current power consumption: %.0fW", c.minerName, power)
	return power, nil
}

// Currents implements the api.PhaseCurrents interface
func (c *BraiinsOS) Currents() (float64, float64, float64, error) {
	power, err := c.CurrentPower()
	if err != nil {
		return 0, 0, 0, err
	}

	if c.voltage <= 0 {
		return 0, 0, 0, fmt.Errorf("invalid voltage: %.2f", c.voltage)
	}

	current := power / c.voltage
	c.log.DEBUG.Printf("%s: Calculated current: %.2fA from %.0fW at %.0fV", c.minerName, current, power, c.voltage)
	return current, 0, 0, nil
}

// Status implements the api.Charger interface (REMOVED: Daily session reset)
func (c *BraiinsOS) Status() (api.ChargeStatus, error) {
	status, err := c.getMinerStatus()
	if err != nil {
		return api.StatusNone, err
	}

	switch status {
	case MinerStatusMining:
		return api.StatusC, nil
	case MinerStatusPaused:
		return api.StatusB, nil
	case MinerStatusIdle:
		return api.StatusB, nil
	case MinerStatusDegraded:
		return api.StatusC, nil
	case MinerStatusError:
		return api.StatusNone, nil
	default:
		return api.StatusNone, nil
	}
}

// Enabled implements the api.Charger interface
func (c *BraiinsOS) Enabled() (bool, error) {
	status, err := c.getMinerStatus()
	if err != nil {
		return false, err
	}
	return status == MinerStatusMining || status == MinerStatusDegraded, nil
}

// Enable implements the api.Charger interface
func (c *BraiinsOS) Enable(enable bool) error {
	endpoint := apiPathPause
	operation := "pause"
	if enable {
		endpoint = apiPathResume
		operation = "resume"
	}

	resp, err := c.authRequest(http.MethodPut, endpoint, nil)
	if err != nil {
		return err
	}
	defer c.closeResponseBody(resp)

	if err := c.handleHTTPResponse(resp, operation); err != nil {
		return err
	}

	c.log.DEBUG.Printf("%s: Miner %s successful", c.minerName, operation)
	return nil
}

// getMinCurrent returns the minimum current based on hardware or DPS constraints
func (c *BraiinsOS) getMinCurrent() float64 {
	voltage := c.voltage
	if voltage <= 0 {
		c.log.WARN.Printf("%s: Invalid voltage %.2f, using 230V default", c.minerName, c.voltage)
		voltage = 230.0
	}

	minWatts := c.minWatts
	if c.dpsActive && c.dpsMinTarget > 0 {
		minWatts = c.dpsMinTarget
		c.log.DEBUG.Printf("%s: Using DPS minimum: %dW", c.minerName, minWatts)
	} else {
		c.log.DEBUG.Printf("%s: Using hardware minimum: %dW", c.minerName, minWatts)
	}

	return float64(minWatts) / voltage
}

// MaxCurrent implements the api.Charger interface - compatibility wrapper
func (c *BraiinsOS) MaxCurrent(current int64) error {
	return c.MaxCurrentMillis(float64(current))
}

// calculateDPSTarget calculates optimal power target for DPS cooperation
func (c *BraiinsOS) calculateDPSTarget(powerRequest float64) int {
	dpsMinimum := c.dpsMinTarget
	if dpsMinimum <= 0 {
		dpsMinimum = c.minWatts
	}

	dpsStep := c.dpsActiveStep
	if dpsStep <= 0 {
		dpsStep = 300
	}

	requestInt := int(math.Round(powerRequest))
	if requestInt <= dpsMinimum {
		return dpsMinimum
	}

	stepsNeeded := int(math.Round(float64(requestInt-dpsMinimum) / float64(dpsStep)))
	if stepsNeeded < 0 {
		stepsNeeded = 0
	}

	targetPower := dpsMinimum + stepsNeeded*dpsStep
	effectiveMax := c.getEffectiveMaxPower()
	if targetPower > effectiveMax {
		targetPower = effectiveMax
	}

	return targetPower
}

// MaxCurrentMillis implements precise decimal ampere control
func (c *BraiinsOS) MaxCurrentMillis(current float64) error {
	if current < 0 {
		return fmt.Errorf("invalid negative current value: %.2f", current)
	}

	if current == 0 {
		return c.Enable(false)
	}

	minCurrent := c.getMinCurrent()

	if current < minCurrent {
		current = minCurrent
	}

	powerRequest := current * c.voltage

	if !c.powerTargetEnabled {
		if !c.powerTargetWarned {
			c.log.INFO.Printf("%s: Using on/off control (PowerTarget not available)", c.minerName)
			c.powerTargetWarned = true
		}

		// Check if miner is already enabled to avoid unnecessary API calls
		enabled, err := c.Enabled()
		if err != nil {
			return err
		}

		// Only enable if not already running
		if !enabled {
			return c.Enable(true)
		}

		return nil
	}

	var targetPowerInt int

	if c.dpsActive {
		targetPowerInt = c.calculateDPSTarget(powerRequest)
	} else {
		effectiveMax := c.getEffectiveMaxPower()
		stepSize := c.powerTargetStep
		minLimit := c.minWatts

		if stepSize >= effectiveMax {
			stepSize = 1
		}

		limitedPower := math.Max(float64(minLimit), powerRequest)
		limitedPower = math.Min(float64(effectiveMax), limitedPower)

		steps := int(math.Ceil(limitedPower / float64(stepSize)))
		targetPowerInt = steps * stepSize

		if targetPowerInt > effectiveMax {
			targetPowerInt = effectiveMax
		}
		if targetPowerInt < minLimit {
			targetPowerInt = minLimit
		}
	}

	// Thread-safe rate limiting
	c.mu.Lock()
	timeSinceLastUpdate := time.Since(c.lastPowerUpdate)
	powerChange := targetPowerInt != c.lastPowerTarget
	shouldWait := c.powerTargetInterval > 10*time.Second && timeSinceLastUpdate < c.powerTargetInterval
	var waitTime time.Duration
	if shouldWait {
		waitTime = c.powerTargetInterval - timeSinceLastUpdate
	}
	c.mu.Unlock()

	if !powerChange {
		return nil
	}

	// Rate limiting outside mutex
	if shouldWait {
		time.Sleep(waitTime)
	}

	// Set power target
	if err := c.setPowerTarget(targetPowerInt); err != nil {
		return err
	}

	// Check if miner is already enabled to avoid unnecessary API calls
	enabled, err := c.Enabled()
	if err != nil {
		return err
	}

	// Only enable if not already running
	if !enabled {
		return c.Enable(true)
	}

	return nil
}

var _ api.Charger = (*BraiinsOS)(nil)
var _ api.ChargerEx = (*BraiinsOS)(nil)
var _ api.Meter = (*BraiinsOS)(nil)
var _ api.PhaseCurrents = (*BraiinsOS)(nil)
