// Native Go implementation for Braiins OS evcc integration
// https://developer.braiins-os.com/latest/openapi.html
// - For dynamic power control: Enable "Power Target" mode in Braiins OS tuner settings
// - Without Power Target: Only on/off control available
// - Also enable DPS-Mode if needed
// Version: 1.8.4 (Fixed stepSize >= effectiveMax mathematical impossibility)
// Version: 1.8.5 (Added FIX 1: Rounding Logic Bug - KRITISCH)

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

// Miner status constants from OpenAPI specification
const (
	MinerStatusUnspecified = 0 // Unspecified status
	MinerStatusIdle        = 1 // Miner is idle
	MinerStatusMining      = 2 // Miner is mining
	MinerStatusPaused      = 3 // Miner is paused
	MinerStatusDegraded    = 4 // Miner performance is degraded
	MinerStatusError       = 5 // Miner is in error state
)

// API endpoints
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

// BraiinsOS charger implementation
type BraiinsOS struct {
	*request.Helper
	*embed
	uri            string
	user           string
	password       string
	configMaxPower int
	voltage        float64
	minerName      string

	// Configurable rate limiting and stepping parameters
	powerTargetInterval time.Duration
	powerTargetStep     int

	// Hardware constraints discovered from miner
	minWatts     int
	defaultWatts int
	maxWatts     int

	// Power target capability and warning state
	powerTargetEnabled bool
	powerTargetWarned  bool

	// Simple DPS detection and status
	dpsDetected   bool // DPS hardware support detected
	dpsActive     bool // DPS currently enabled
	dpsMinTarget  int  // DPS minimum from constraints
	dpsActiveStep int  // DPS step from active config

	// Thread-safe fields protected by mutex
	mu              sync.Mutex
	token           string
	tokenExpiry     time.Time
	lastPowerUpdate time.Time
	lastPowerTarget int

	log *util.Logger
}

// BraiinsConfig is the configuration struct
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

// Login request/response structures
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token    string `json:"token"`
	TimeoutS int    `json:"timeout_s"`
}

// MinerDetails for status detection
type MinerDetails struct {
	Status int `json:"status"`
}

// MinerStats for power measurement
type MinerStats struct {
	PowerStats struct {
		ApproximatedConsumption struct {
			Watt int `json:"watt"`
		} `json:"approximated_consumption"`
	} `json:"power_stats"`
}

// PowerTarget structures
type PowerTarget struct {
	Watt int `json:"watt"`
}

// NetworkConfiguration for hostname discovery
type NetworkConfiguration struct {
	Hostname string                 `json:"hostname"`
	Protocol map[string]interface{} `json:"protocol,omitempty"`
}

// MinerConfiguration for DPS status detection
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

// ConfigConstraints for power limits and DPS detection
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

	// Set defaults for missing configuration values
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
		cc.PowerTargetInterval = 30 * time.Second
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

	hostname := strings.TrimSuffix(config.Hostname, ".local")
	return hostname
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

	// Test connection and get initial token
	if err := c.login(); err != nil {
		return nil, fmt.Errorf("connection test failed: %w", err)
	}

	// Determine miner name for logging
	c.minerName = c.determineMinerName()
	c.log.INFO.Printf("%s: Braiins miner connected at %s", c.minerName, uri)

	// Discover miner constraints and DPS detection
	if err := c.discoverConstraints(); err != nil {
		return nil, fmt.Errorf("failed to get miner constraints: %w", err)
	}

	// Discover actual DPS status
	if err := c.discoverDpsStatus(); err != nil {
		return nil, fmt.Errorf("failed to get DPS status: %w", err)
	}

	// Validate configuration
	if c.configMaxPower > 0 && c.configMaxPower < c.minWatts {
		return nil, fmt.Errorf("configured maxPower (%dW) below hardware minimum (%dW)", c.configMaxPower, c.minWatts)
	}

	// Log configuration summary
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

	return c, nil
}

// login gets a new authentication token with thread-safe token management
func (c *BraiinsOS) login() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Now().Before(c.tokenExpiry) && c.token != "" {
		return nil // Token still valid
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

		req.Header.Set("Authorization", token)
		return c.Do(req)
	}

	// Try once, retry on 401
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

			continue // Retry
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
		return nil // 204 No Content is success for PUT operations
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s failed: %s (HTTP %d)", operation, resp.Status, resp.StatusCode)
	}
	return nil
}

// closeResponseBody safely closes response body
func (c *BraiinsOS) closeResponseBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		if err := resp.Body.Close(); err != nil {
			c.log.DEBUG.Printf("%s: Failed to close response body: %v", c.minerName, err)
		}
	}
}

// discoverConstraints gets miner power limits and detects DPS support
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

	// Hardware constraints
	c.minWatts = constraints.TunerConstraints.PowerTarget.Min.Watt
	c.defaultWatts = constraints.TunerConstraints.PowerTarget.Default.Watt
	c.maxWatts = constraints.TunerConstraints.PowerTarget.Max.Watt

	// Power target support detection
	c.powerTargetEnabled = c.minWatts > 0 && c.defaultWatts > 0 && c.maxWatts > 0

	// Simple DPS detection
	dpsStep := constraints.DpsConstraints.PowerStep.Default.Watt
	dpsMinTarget := constraints.DpsConstraints.MinPowerTarget.Default.Watt
	c.dpsDetected = dpsStep > 0 && dpsMinTarget > 0

	if c.dpsDetected {
		c.dpsMinTarget = dpsMinTarget
		c.log.INFO.Printf("%s: DPS hardware detected: min=%dW, step=%dW", c.minerName, dpsMinTarget, dpsStep)
	}

	c.log.DEBUG.Printf("%s: Constraints - min=%dW, default=%dW, max=%dW, powerTarget=%v, dps=%v",
		c.minerName, c.minWatts, c.defaultWatts, c.maxWatts, c.powerTargetEnabled, c.dpsDetected)

	return nil
}

// discoverDpsStatus checks if DPS is actually active
func (c *BraiinsOS) discoverDpsStatus() error {
	if !c.dpsDetected {
		return nil // Skip if no DPS hardware
	}

	resp, err := c.authRequest(http.MethodGet, apiPathMinerConfig, nil)
	if err != nil {
		c.log.WARN.Printf("%s: Could not check DPS status: %v", c.minerName, err)
		return nil // Non-fatal
	}
	defer c.closeResponseBody(resp)

	if err := c.handleHTTPResponse(resp, "miner config request"); err != nil {
		c.log.WARN.Printf("%s: Miner config request failed: %v", c.minerName, err)
		return nil // Non-fatal
	}

	var config MinerConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		c.log.WARN.Printf("%s: Could not decode miner config: %v", c.minerName, err)
		return nil // Non-fatal
	}

	c.dpsActive = config.Dps.Enabled
	c.dpsActiveStep = config.Dps.PowerStep.Watt

	if c.dpsActive {
		c.log.INFO.Printf("%s: DPS is active - evcc will cooperate with DPS control", c.minerName)
		c.log.INFO.Printf("%s: DPS configuration: step=%dW, mode=%d", c.minerName, c.dpsActiveStep, config.Dps.Mode)
	} else {
		c.log.INFO.Printf("%s: DPS available but inactive - evcc has full control", c.minerName)
	}

	return nil
}

// getEffectiveMaxPower returns the effective maximum power for evcc control
func (c *BraiinsOS) getEffectiveMaxPower() int {
	effectiveMax := c.defaultWatts
	if c.configMaxPower > 0 {
		effectiveMax = c.configMaxPower
	}

	effectiveMax = int(math.Min(float64(effectiveMax), float64(c.maxWatts)))
	effectiveMax = int(math.Max(float64(effectiveMax), float64(c.minWatts)))

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

	// Enhanced error handling for DPS conflicts
	switch resp.StatusCode {
	case http.StatusForbidden:
		// Read limited error body for debugging
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

	// Update tracking
	c.mu.Lock()
	c.lastPowerTarget = targetWatts
	c.lastPowerUpdate = time.Now()
	c.mu.Unlock()

	c.log.INFO.Printf("%s: Power target set successfully: %dW", c.minerName, targetWatts)
	return nil
}

// Status implements the api.Charger interface
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
		return api.StatusA, nil
	case MinerStatusDegraded:
		return api.StatusC, nil // Still mining
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

// MaxCurrent implements the api.Charger interface - WITH BOTH FIXES
func (c *BraiinsOS) MaxCurrent(current int64) error {
	c.log.INFO.Printf("%s: MaxCurrent called with %dA", c.minerName, current)

	// Validate input
	if current < 0 {
		return fmt.Errorf("invalid negative current value: %d", current)
	}

	if current == 0 {
		c.log.DEBUG.Printf("%s: Current=0A - pausing miner", c.minerName)
		return c.Enable(false)
	}

	// Calculate desired power
	powerRequest := float64(current) * c.voltage
	c.log.INFO.Printf("%s: Requested %.1fA at %.0fV = %.0fW power", c.minerName, float64(current), c.voltage, powerRequest)

	// Check minimum hardware requirements
	if powerRequest < float64(c.minWatts) {
		c.log.INFO.Printf("%s: Requested %.0fW insufficient for hardware minimum (%dW) - pausing miner", c.minerName, powerRequest, c.minWatts)
		return c.Enable(false)
	}

	// FALL 1: Power target mode not available - simple on/off
	if !c.powerTargetEnabled {
		c.log.DEBUG.Printf("%s: Power target mode not available - using simple on/off control", c.minerName)
		if !c.powerTargetWarned {
			c.log.WARN.Printf("%s: Enable Power Target in Braiins OS for dynamic power control", c.minerName)
			c.powerTargetWarned = true
		}
		return c.Enable(true)
	}

	effectiveMax := c.getEffectiveMaxPower()
	if effectiveMax <= c.minWatts {
		c.log.WARN.Printf("%s: Effective max power (%dW) too low - using minimum (%dW)", c.minerName, effectiveMax, c.minWatts)
		if err := c.setPowerTarget(c.minWatts); err != nil {
			return err
		}
		return c.Enable(true)
	}

	var targetPower float64
	var stepSize int
	var minLimit int

	// FALL 2 & 3: Power target available - choose logic based on DPS status
	if c.dpsActive {
		// FALL 3: DPS ACTIVE - use DPS constraints
		c.log.INFO.Printf("%s: DPS is active - using DPS constraints", c.minerName)
		minLimit = c.dpsMinTarget
		stepSize = c.dpsActiveStep
		if stepSize <= 0 {
			stepSize = 100 // fallback
		}
		if minLimit <= 0 {
			minLimit = c.minWatts
		}
	} else {
		// FALL 2: DPS NOT ACTIVE - evcc has full control (like v1.4.2)
		c.log.INFO.Printf("%s: DPS inactive - evcc has full control", c.minerName)
		minLimit = c.minWatts
		stepSize = c.powerTargetStep
	}

	// FIX: Mathematical impossibility check - prevent stepSize >= effectiveMax
	if stepSize >= effectiveMax {
		c.log.INFO.Printf("%s: Step size (%dW) >= max power (%dW) - using 1W steps for precise control",
			c.minerName, stepSize, effectiveMax)
		stepSize = 1
	}

	// Apply power limits - EXACTLY like v1.4.2
	targetPower = math.Max(float64(minLimit), powerRequest)
	targetPower = math.Min(float64(effectiveMax), targetPower)

	// Round down using step size
	targetPower = math.Floor(targetPower/float64(stepSize)) * float64(stepSize)
	targetPowerInt := int(targetPower)

	// FIX 1: Ensure rounding doesn't drop below minLimit (critical bug fix)
	if targetPowerInt < minLimit {
		targetPowerInt = minLimit // Never go below hardware minimum
		c.log.DEBUG.Printf("%s: Rounded power (%dW) below minimum, clamped to %dW", c.minerName, int(targetPower), minLimit)
	}

	c.log.INFO.Printf("%s: Power calculation: %.0fW -> %dW (min: %dW, step: %dW, %s)",
		c.minerName, powerRequest, targetPowerInt, minLimit, stepSize,
		func() string {
			if c.dpsActive {
				return "DPS mode"
			}
			return "evcc mode"
		}())

	// Rate limiting - EXACTLY like v1.4.2
	c.mu.Lock()
	timeSinceLastUpdate := time.Since(c.lastPowerUpdate)
	powerChange := targetPowerInt != c.lastPowerTarget
	lastTarget := c.lastPowerTarget
	c.mu.Unlock()

	if !powerChange {
		c.log.DEBUG.Printf("%s: Power target unchanged at %dW, skipping update", c.minerName, lastTarget)
		return nil
	}

	if timeSinceLastUpdate < c.powerTargetInterval {
		c.log.DEBUG.Printf("%s: Rate limiting: %.0fs since last update, delaying power change to %dW",
			c.minerName, timeSinceLastUpdate.Seconds(), targetPowerInt)
		return nil
	}

	// FIX 2: Don't enable miner if target is 0W (critical bug fix)
	if targetPowerInt == 0 {
		c.log.DEBUG.Printf("%s: Power target is 0W - pausing miner instead of enabling", c.minerName)
		return c.Enable(false)
	}

	// Set power target and enable
	if err := c.setPowerTarget(targetPowerInt); err != nil {
		return err
	}

	return c.Enable(true)
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

// Interface compliance checks
var _ api.Charger = (*BraiinsOS)(nil)
var _ api.Meter = (*BraiinsOS)(nil)
var _ api.PhaseCurrents = (*BraiinsOS)(nil)
