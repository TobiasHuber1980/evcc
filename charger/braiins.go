// Native Go implementation for Braiins OS evcc integration
// https://developer.braiins-os.com/latest/openapi.html
// For dynamic power control: Enable "Power Target" mode in Braiins OS tuner settings
// Without Power Target: Only on/off control available
// Also enable DPS-Mode if needed
// Version: 0.1

// LICENSE
// Copyright (c) Tobias W. Huber https://github.com/TobiasHuber1980/
// This module is NOT covered by the MIT license. All rights reserved.
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
	defaultPowerTargetInterval  = 15 * time.Second
	defaultPowerTargetStep      = 100
	defaultMinDecreaseDuration  = 15 * time.Minute
	defaultDecreaseStepInterval = 5 * time.Minute
	defaultDPSStep              = 300
	defaultConsistencyChecks    = 5
	defaultRecentRequestsLimit  = 10

	lowPowerThreshold        = 0.85 // 85% of current target
	requiredConsistencyRatio = 0.80 // 4 out of 5 checks
	tokenExpiryBufferSeconds = 30
	defaultTokenTimeout      = 1 * time.Hour
	maxResponseBodyBytes     = 512
	minIntervalForWait       = 10 * time.Second
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

	// Connection settings
	uri      string
	user     string
	password string

	// Configuration
	config PowerControlConfig

	// Hardware capabilities
	hardware HardwareCapabilities

	// Power target state
	powerState PowerTargetState

	// DPS state
	dps DPSState

	// Intelligent decrease
	intelligentDecrease IntelligentDecreaseController

	// Authentication
	auth AuthState

	// Session management
	session SessionState

	// External dependencies
	lp  loadpoint.API
	log *util.Logger
	mu  sync.Mutex
}

// PowerControlConfig holds user configuration
type PowerControlConfig struct {
	MaxPower            int
	Voltage             float64
	PowerTargetInterval time.Duration
	PowerTargetStep     int
	DailyResetEnabled   bool
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
	Enabled      bool
	LastTarget   int
	LastUpdate   time.Time
	WarningShown bool
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

	// State
	LowPowerStart    time.Time
	LastDecreaseStep time.Time

	// Ring buffer for power requests (fixed size for efficiency)
	RecentRequests     [defaultRecentRequestsLimit]float64
	RecentRequestTimes [defaultRecentRequestsLimit]time.Time
	RequestIndex       int // Current write position
	RequestCount       int // Number of valid entries (0-10)
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
	PowerTargetInterval  time.Duration `mapstructure:"powerTargetInterval"`
	PowerTargetStep      int           `mapstructure:"powerTargetStep"`
	DailyReset           bool          `mapstructure:"dailyReset"`
	IntelligentDecrease  bool          `mapstructure:"intelligentDecrease"`
	MinDecreaseDuration  time.Duration `mapstructure:"minDecreaseDuration"`
	DecreaseStepInterval time.Duration `mapstructure:"decreaseStepInterval"`
}

// API request/response types
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

// ensureScheme adds http:// prefix if no scheme is present
func ensureScheme(u string) string {
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	return "http://" + u
}

// NewBraiinsFromConfig creates a new Braiins instance from configuration
func NewBraiinsFromConfig(other map[string]any) (api.Charger, error) {
	cc := applyConfigDefaults(other)

	uri := ensureScheme(cc.URI)
	return NewBraiins(uri, cc.User, cc.Password, cc.Timeout, cc.MaxPower, cc.Voltage,
		cc.PowerTargetInterval, cc.PowerTargetStep, cc.DailyReset,
		cc.IntelligentDecrease, cc.MinDecreaseDuration, cc.DecreaseStepInterval)
}

// applyConfigDefaults applies default values to the configuration
func applyConfigDefaults(other map[string]any) BraiinsConfig {
	var cc BraiinsConfig
	if err := util.DecodeOther(other, &cc); err != nil {
		// Return empty config, will be caught by validation
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
	if cc.PowerTargetInterval == 0 {
		cc.PowerTargetInterval = defaultPowerTargetInterval
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

// NewBraiins creates a new Braiins OS charger instance
func NewBraiins(uri, user, password string, timeout time.Duration, maxPower int, voltage float64,
	powerTargetInterval time.Duration, powerTargetStep int, dailyReset bool,
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
			MaxPower:            maxPower,
			Voltage:             voltage,
			PowerTargetInterval: powerTargetInterval,
			PowerTargetStep:     powerTargetStep,
			DailyResetEnabled:   dailyReset,
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

// initialize performs initial setup and validation
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

// validateConfiguration checks if configuration is valid for hardware
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

// determineMinerName extracts hostname from URI
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

// tryGetHostname attempts to retrieve the miner's configured hostname
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

// tryUpdateHostname updates miner name if hostname is available
func (c *BraiinsOS) tryUpdateHostname() {
	hostname := c.tryGetHostname()
	if hostname == "" || hostname == c.hardware.Name {
		return
	}

	c.mu.Lock()
	c.hardware.Name = hostname
	c.mu.Unlock()
}

// displayConfigurationSummary logs the current configuration
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

// logPowerTargetConfiguration logs configuration when power target is enabled
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

// logDPSStatus logs DPS configuration status
func (c *BraiinsOS) logDPSStatus() {
	if c.dps.Active {
		c.log.INFO.Printf("%s: DPS ACTIVE: %dW (min) - %dW (step)",
			c.hardware.Name, c.dps.MinTarget, c.dps.ActiveStep)
	} else if c.dps.Detected {
		c.log.INFO.Printf("%s: DPS detected but INACTIVE - evcc has full control", c.hardware.Name)
	}
}

// logMaxPowerSource logs the source of max power setting
func (c *BraiinsOS) logMaxPowerSource(effectiveMax int) {
	maxLabel := "Default"
	if c.config.MaxPower > 0 {
		maxLabel = "User-Setting"
	}

	resetInfo := ""
	if c.config.DailyResetEnabled {
		resetInfo = ", daily reset: enabled"
	}

	c.log.INFO.Printf("%s: evcc configuration: %dW - %dW (%s), %.0fV, interval: %v, step: %dW%s",
		c.hardware.Name, c.hardware.MinWatts, effectiveMax, maxLabel,
		c.config.Voltage, c.config.PowerTargetInterval, c.config.PowerTargetStep, resetInfo)
}

// logIntelligentDecreaseStatus logs intelligent decrease configuration
func (c *BraiinsOS) logIntelligentDecreaseStatus() {
	if c.intelligentDecrease.Enabled {
		c.log.INFO.Printf("%s: Intelligent decrease: ENABLED - wait: %v, step interval: %v",
			c.hardware.Name, c.intelligentDecrease.MinDecreaseDuration,
			c.intelligentDecrease.DecreaseStepInterval)
	} else {
		c.log.INFO.Printf("%s: Intelligent decrease: DISABLED - immediate response", c.hardware.Name)
	}
}

// logOnOffConfiguration logs configuration when only on/off control is available
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

// Authentication methods

// login authenticates with the miner and retrieves a token
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

// updateAuthToken updates the authentication token and expiry
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

// authRequest performs an authenticated HTTP request
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

// performAuthRequest performs a single authenticated request
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

// createAuthenticatedRequest creates an HTTP request with auth token
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

// handleUnauthorized handles 401 responses by clearing auth state
func (c *BraiinsOS) handleUnauthorized(resp *http.Response) {
	c.log.WARN.Printf("%s: Token invalid (401), attempting re-authentication", c.hardware.Name)
	c.closeResponseBody(resp)

	c.mu.Lock()
	c.auth.Token = ""
	c.auth.TokenExpiry = time.Time{}
	c.mu.Unlock()
}

// HTTP response handling

// handleHTTPResponse checks HTTP response status and returns error if needed
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

// closeResponseBody safely closes response body
func (c *BraiinsOS) closeResponseBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
}

// Hardware discovery methods

// discoverConstraints retrieves hardware power constraints
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

// updateHardwareCapabilities updates hardware limits from constraints
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

// discoverMinerStatus retrieves current miner configuration
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

// updatePowerTargetState updates power target state from config
func (c *BraiinsOS) updatePowerTargetState(config MinerConfiguration) {
	c.powerState.Enabled = config.Tuner.Enabled && c.hardware.MaxWatts > 0

	if c.powerState.Enabled {
		currentTarget := c.hardware.DefaultWatts
		if config.Tuner.PowerTarget != nil {
			currentTarget = config.Tuner.PowerTarget.Watt
			c.powerState.LastTarget = currentTarget
		}
		c.log.DEBUG.Printf("%s: PowerTarget detected: %dW", c.hardware.Name, currentTarget)
	}
}

// updateDPSState updates DPS state from config
func (c *BraiinsOS) updateDPSState(config MinerConfiguration) {
	c.dps.Active = config.DPS.Enabled
	c.dps.ActiveStep = config.DPS.PowerStep.Watt

	if c.dps.Detected && c.dps.Active {
		c.log.DEBUG.Printf("%s: DPS configuration: min=%dW, step=%dW",
			c.hardware.Name, c.dps.MinTarget, c.dps.ActiveStep)
	}
}

// Power calculation methods

// getEffectiveMaxPower returns the maximum power considering configuration
func (c *BraiinsOS) getEffectiveMaxPower() int {
	effectiveMax := c.hardware.DefaultWatts
	if c.config.MaxPower > 0 {
		effectiveMax = c.config.MaxPower
	}

	if effectiveMax > c.hardware.MaxWatts {
		effectiveMax = c.hardware.MaxWatts
	}
	if effectiveMax < c.hardware.MinWatts {
		effectiveMax = c.hardware.MinWatts
	}

	return effectiveMax
}

// getMinCurrent calculates minimum current based on voltage and power
func (c *BraiinsOS) getMinCurrent() float64 {
	voltage := c.config.Voltage
	if voltage <= 0 {
		c.log.WARN.Printf("%s: Invalid voltage %.2f, using 230V default",
			c.hardware.Name, c.config.Voltage)
		voltage = defaultVoltage
	}

	minWatts := c.hardware.MinWatts
	if c.dps.Active && c.dps.MinTarget > 0 {
		minWatts = c.dps.MinTarget
	}

	return float64(minWatts) / voltage
}

// calculateDPSTarget calculates target power aligned to DPS steps
func (c *BraiinsOS) calculateDPSTarget(powerRequest float64) int {
	dpsMinimum := c.dps.MinTarget
	if dpsMinimum <= 0 {
		dpsMinimum = c.hardware.MinWatts
	}

	dpsStep := c.dps.ActiveStep
	if dpsStep <= 0 {
		dpsStep = defaultDPSStep
	}

	requestInt := int(math.Round(powerRequest))
	if requestInt <= dpsMinimum {
		return dpsMinimum
	}

	// Better rounding: add half step before division to avoid .5 issues
	stepsNeeded := max(0, int((float64(requestInt-dpsMinimum)+float64(dpsStep)/2)/float64(dpsStep)))

	targetPower := dpsMinimum + stepsNeeded*dpsStep
	effectiveMax := c.getEffectiveMaxPower()
	if targetPower > effectiveMax {
		targetPower = effectiveMax
	}

	return targetPower
}

// calculateTargetPower calculates target power with stepping
func (c *BraiinsOS) calculateTargetPower(powerRequest float64, isIncreasing bool) int {
	if c.dps.Active {
		return c.calculateDPSTarget(powerRequest)
	}

	effectiveMax := c.getEffectiveMaxPower()
	stepSize := c.config.PowerTargetStep
	minLimit := c.hardware.MinWatts

	if stepSize >= effectiveMax {
		stepSize = 1
	}

	limitedPower := math.Max(float64(minLimit), powerRequest)
	limitedPower = math.Min(float64(effectiveMax), limitedPower)

	var steps int
	if isIncreasing {
		steps = int(math.Ceil(limitedPower / float64(stepSize)))
	} else {
		steps = int(math.Round(limitedPower / float64(stepSize)))
	}

	targetPowerInt := steps * stepSize

	// Clamp between min and max using built-in functions
	targetPowerInt = max(minLimit, min(targetPowerInt, effectiveMax))

	return targetPowerInt
}

// Miner status and control

// getMinerStatus retrieves current miner status
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

// setPowerTarget sets the miner's power target
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
	c.mu.Unlock()

	c.log.INFO.Printf("%s: Power target set successfully: %dW", c.hardware.Name, targetWatts)
	return nil
}

// handlePowerTargetResponse handles power target response errors
func (c *BraiinsOS) handlePowerTargetResponse(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusForbidden:
		c.logPowerTargetError(resp, "BLOCKED", 403)
		return fmt.Errorf("power target blocked by DPS (HTTP 403)")
	case http.StatusConflict:
		c.log.ERROR.Printf("%s: Power target CONFLICT (409) - DPS interference", c.hardware.Name)
		return fmt.Errorf("power target conflict with DPS (HTTP 409)")
	}

	return c.handleHTTPResponse(resp, "set power target")
}

// logPowerTargetError logs detailed power target error
func (c *BraiinsOS) logPowerTargetError(resp *http.Response, errorType string, statusCode int) {
	if resp.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
		if len(body) > 0 {
			c.log.DEBUG.Printf("%s: Error response body: %s", c.hardware.Name, string(body))
		}
	}
	c.log.ERROR.Printf("%s: Power target %s (%d) - DPS conflict detected",
		c.hardware.Name, errorType, statusCode)
	if c.dps.Active {
		c.log.ERROR.Printf("%s: DPS is active - disable DPS for full evcc control", c.hardware.Name)
	}
}

// Intelligent power decrease methods

// shouldActuallyDecrease determines if power should be decreased
func (c *BraiinsOS) shouldActuallyDecrease(requestedPower float64) (bool, float64) {
	if !c.intelligentDecrease.Enabled {
		return true, requestedPower
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.trackPowerRequest(requestedPower)

	currentTarget := c.powerState.LastTarget
	isLow := requestedPower < float64(currentTarget)*lowPowerThreshold

	if isLow {
		return c.evaluateLowPowerCondition(requestedPower, currentTarget)
	}

	return c.handlePowerRecovery(), float64(currentTarget)
}

// trackPowerRequest adds current request to history using ring buffer
func (c *BraiinsOS) trackPowerRequest(requestedPower float64) {
	now := time.Now()

	// Write to current index
	c.intelligentDecrease.RecentRequests[c.intelligentDecrease.RequestIndex] = requestedPower
	c.intelligentDecrease.RecentRequestTimes[c.intelligentDecrease.RequestIndex] = now

	// Move index forward (wrap around at limit)
	c.intelligentDecrease.RequestIndex = (c.intelligentDecrease.RequestIndex + 1) % defaultRecentRequestsLimit

	// Increment count until we reach limit
	if c.intelligentDecrease.RequestCount < defaultRecentRequestsLimit {
		c.intelligentDecrease.RequestCount++
	}
}

// evaluateLowPowerCondition evaluates if decrease should proceed
func (c *BraiinsOS) evaluateLowPowerCondition(requestedPower float64, currentTarget int) (bool, float64) {
	now := time.Now()

	// Start timer on first low request
	if c.intelligentDecrease.LowPowerStart.IsZero() {
		c.intelligentDecrease.LowPowerStart = now
		c.log.INFO.Printf("%s: Insufficient solar detected - starting 15min wait timer (miner continues at current power)",
			c.hardware.Name)
	}

	lowDuration := now.Sub(c.intelligentDecrease.LowPowerStart)

	// Timer 1: Check if minimum duration has passed
	if lowDuration < c.intelligentDecrease.MinDecreaseDuration {
		remaining := c.intelligentDecrease.MinDecreaseDuration - lowDuration
		c.log.INFO.Printf("%s: Wait timer: %v elapsed, %v remaining (miner maintaining current power)",
			c.hardware.Name, lowDuration.Round(time.Second), remaining.Round(time.Second))
		return false, float64(currentTarget)
	}

	// Check consistency
	if !c.hasConsistentLowPower(currentTarget) {
		return false, float64(currentTarget)
	}

	// Timer 1 complete - return average for calculation
	// Actual decrease step will be logged when it happens (after Timer 2 check)
	avgPower := c.calculateAveragePower()
	return true, avgPower
}

// hasConsistentLowPower checks if recent requests are consistently low
func (c *BraiinsOS) hasConsistentLowPower(currentTarget int) bool {
	requiredSamples := c.intelligentDecrease.ConsistencyChecks
	if c.intelligentDecrease.RequestCount < requiredSamples {
		c.log.DEBUG.Printf("%s: Not enough samples yet (%d/%d) - ignoring",
			c.hardware.Name, c.intelligentDecrease.RequestCount, requiredSamples)
		return false
	}

	lowCount := 0
	threshold := float64(currentTarget) * lowPowerThreshold

	// Read last N samples from ring buffer
	for i := range requiredSamples {
		// Calculate actual index: go backwards from current position
		idx := (c.intelligentDecrease.RequestIndex - 1 - i + defaultRecentRequestsLimit) % defaultRecentRequestsLimit
		if c.intelligentDecrease.RecentRequests[idx] < threshold {
			lowCount++
		}
	}

	requiredLow := int(float64(requiredSamples) * requiredConsistencyRatio)
	if lowCount < requiredLow {
		c.log.DEBUG.Printf("%s: Only %d/%d checks low (need %d) - ignoring",
			c.hardware.Name, lowCount, requiredSamples, requiredLow)
		return false
	}

	return true
}

// calculateAveragePower calculates average of recent requests
func (c *BraiinsOS) calculateAveragePower() float64 {
	requiredSamples := c.intelligentDecrease.ConsistencyChecks

	sum := 0.0
	// Read last N samples from ring buffer
	for i := range requiredSamples {
		// Calculate actual index: go backwards from current position
		idx := (c.intelligentDecrease.RequestIndex - 1 - i + defaultRecentRequestsLimit) % defaultRecentRequestsLimit
		sum += c.intelligentDecrease.RecentRequests[idx]
	}

	return sum / float64(requiredSamples)
}

// handlePowerRecovery handles power recovery scenario
func (c *BraiinsOS) handlePowerRecovery() bool {
	if !c.intelligentDecrease.LowPowerStart.IsZero() {
		duration := time.Since(c.intelligentDecrease.LowPowerStart)
		c.log.INFO.Printf("%s: Solar power recovered after %v - canceling decrease timer, maintaining power",
			c.hardware.Name, duration.Round(time.Second))
		c.intelligentDecrease.LowPowerStart = time.Time{}
	}
	return false
}

// handlePowerDecrease handles gradual power decrease
func (c *BraiinsOS) handlePowerDecrease(originalRequest, clippedRequest float64, currentTarget int, wasClipped bool) (float64, error) {
	// Timer 1: Use ORIGINAL request (not clipped) for timer decision
	shouldDecrease, avgPower := c.shouldActuallyDecrease(originalRequest)
	if !shouldDecrease {
		// Timer not expired yet - keep current (clipped) request
		return clippedRequest, nil
	}

	// Timer 1 has expired!
	// If we're already at minimum (wasClipped), turn off miner
	if wasClipped {
		c.log.INFO.Printf("%s: Wait timer expired while at minimum power - insufficient solar, turning off",
			c.hardware.Name)
		c.resetDecreaseTracking()
		return 0, nil // Signal to turn off
	}

	// Timer 2: Check step interval
	c.mu.Lock()
	lastDecreaseStep := c.intelligentDecrease.LastDecreaseStep
	lowPowerStart := c.intelligentDecrease.LowPowerStart
	c.mu.Unlock()

	now := time.Now()

	// Log once when Timer 1 first expires
	if lastDecreaseStep.IsZero() && !lowPowerStart.IsZero() {
		duration := now.Sub(lowPowerStart)
		c.log.INFO.Printf("%s: Wait timer complete after %v - ready to decrease (avg solar: %.0fW)",
			c.hardware.Name, duration.Round(time.Second), avgPower)
	}

	if !lastDecreaseStep.IsZero() {
		timeSinceLastStep := now.Sub(lastDecreaseStep)
		if timeSinceLastStep < c.intelligentDecrease.DecreaseStepInterval {
			waitTime := c.intelligentDecrease.DecreaseStepInterval - timeSinceLastStep
			c.log.DEBUG.Printf("%s: Step interval: %v elapsed, waiting %v more before next step",
				c.hardware.Name, timeSinceLastStep.Round(time.Second),
				waitTime.Round(time.Second))
			return clippedRequest, nil // No change
		}
	}

	return c.calculateGradualDecrease(avgPower, currentTarget, now)
}

// calculateGradualDecrease calculates next step in gradual decrease
func (c *BraiinsOS) calculateGradualDecrease(avgPower float64, currentTarget int, now time.Time) (float64, error) {
	stepSize := c.getDecreaseStepSize()
	oneStepDown := currentTarget - stepSize

	// If next step would be at or below minimum, turn off instead of staying at minimum
	if oneStepDown <= c.hardware.MinWatts {
		c.log.INFO.Printf("%s: Next step (%dW) would be at/below minimum (%dW) - turning off",
			c.hardware.Name, oneStepDown, c.hardware.MinWatts)
		c.resetDecreaseTracking()
		return 0, nil // Signal to turn off
	}

	targetFromAvg := int(math.Round(avgPower/float64(stepSize))) * stepSize

	// If average power is below minimum, turn off instead of clipping
	if targetFromAvg < c.hardware.MinWatts {
		c.log.INFO.Printf("%s: Average power (%dW) below minimum (%dW) - turning off",
			c.hardware.Name, targetFromAvg, c.hardware.MinWatts)
		c.resetDecreaseTracking()
		return 0, nil // Signal to turn off
	}

	if oneStepDown <= targetFromAvg {
		return c.performFinalDecreaseStep(targetFromAvg, currentTarget)
	}

	return c.performIntermediateDecreaseStep(oneStepDown, targetFromAvg, currentTarget, stepSize, now)
}

// getDecreaseStepSize returns the step size for decreasing
func (c *BraiinsOS) getDecreaseStepSize() int {
	stepSize := c.config.PowerTargetStep
	if c.dps.Active && c.dps.ActiveStep > 0 {
		stepSize = c.dps.ActiveStep
	}
	if stepSize == 0 {
		stepSize = defaultDPSStep
	}
	return stepSize
}

// performFinalDecreaseStep performs the final step to target
func (c *BraiinsOS) performFinalDecreaseStep(targetFromAvg, currentTarget int) (float64, error) {
	// Safety check: if target is below minimum, turn off
	if targetFromAvg < c.hardware.MinWatts {
		c.log.INFO.Printf("%s: Final target (%dW) below minimum (%dW) - turning off",
			c.hardware.Name, targetFromAvg, c.hardware.MinWatts)
		c.resetDecreaseTracking()
		return 0, nil
	}

	c.log.INFO.Printf("%s: Final decrease step to target: %dW -> %dW",
		c.hardware.Name, currentTarget, targetFromAvg)

	c.mu.Lock()
	c.intelligentDecrease.LastDecreaseStep = time.Time{}
	c.intelligentDecrease.LowPowerStart = time.Time{}
	c.mu.Unlock()

	return float64(targetFromAvg), nil
}

// performIntermediateDecreaseStep performs an intermediate decrease step
func (c *BraiinsOS) performIntermediateDecreaseStep(oneStepDown, targetFromAvg, currentTarget, stepSize int, now time.Time) (float64, error) {
	stepsRemaining := (oneStepDown - targetFromAvg) / stepSize
	c.log.INFO.Printf("%s: Power decrease step: %dW -> %dW (-%dW, %d more steps to avg target %dW)",
		c.hardware.Name, currentTarget, oneStepDown, stepSize, stepsRemaining, targetFromAvg)

	c.mu.Lock()
	c.intelligentDecrease.LastDecreaseStep = now
	c.mu.Unlock()

	return float64(oneStepDown), nil
}

// resetDecreaseTracking resets intelligent decrease timers
func (c *BraiinsOS) resetDecreaseTracking() {
	c.mu.Lock()
	c.intelligentDecrease.LastDecreaseStep = time.Time{}
	c.intelligentDecrease.LowPowerStart = time.Time{}
	c.mu.Unlock()
}

// Daily reset methods

// checkDailyReset checks and performs daily reset if needed
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

// API interface implementations

// CurrentPower returns the current power consumption
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
	return power, nil
}

// Currents returns the calculated current (single phase)
func (c *BraiinsOS) Currents() (float64, float64, float64, error) {
	power, err := c.CurrentPower()
	if err != nil {
		return 0, 0, 0, err
	}

	if c.config.Voltage <= 0 {
		return 0, 0, 0, fmt.Errorf("invalid voltage: %.2f", c.config.Voltage)
	}

	current := power / c.config.Voltage
	c.log.DEBUG.Printf("%s: Calculated current: %.2fA from %.0fW at %.0fV",
		c.hardware.Name, current, power, c.config.Voltage)
	return current, 0, 0, nil
}

// Status returns the current charge status
func (c *BraiinsOS) Status() (api.ChargeStatus, error) {
	if resetStatus := c.checkDailyReset(); resetStatus != api.StatusNone {
		return resetStatus, nil
	}

	status, err := c.getMinerStatus()
	if err != nil {
		return api.StatusNone, err
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

// mapMinerStatusToChargeStatus maps miner status to charge status
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

// Enabled returns whether the miner is enabled
func (c *BraiinsOS) Enabled() (bool, error) {
	status, err := c.getMinerStatus()
	if err != nil {
		return false, err
	}
	return status == MinerStatusMining || status == MinerStatusDegraded, nil
}

// Enable enables or disables the miner
func (c *BraiinsOS) Enable(enable bool) error {
	endpoint, operation := c.getEnableEndpoint(enable)

	resp, err := c.authRequest(http.MethodPut, endpoint, nil)
	if err != nil {
		return err
	}
	defer c.closeResponseBody(resp)

	if err := c.handleHTTPResponse(resp, operation); err != nil {
		return err
	}

	if !enable {
		c.resetDecreaseTracking()
		c.log.DEBUG.Printf("%s: Intelligent decrease timers reset (miner paused)", c.hardware.Name)
	}

	c.log.DEBUG.Printf("%s: Miner %s successful", c.hardware.Name, operation)
	return nil
}

// getEnableEndpoint returns the appropriate endpoint for enable/disable
func (c *BraiinsOS) getEnableEndpoint(enable bool) (string, string) {
	if enable {
		return apiPathResume, "resume"
	}
	return apiPathPause, "pause"
}

// MaxCurrent sets the maximum current (int64 version)
func (c *BraiinsOS) MaxCurrent(current int64) error {
	return c.MaxCurrentMillis(float64(current))
}

// MaxCurrentMillis sets the maximum current with float precision
func (c *BraiinsOS) MaxCurrentMillis(current float64) error {
	if current < 0 {
		return fmt.Errorf("invalid negative current value: %.2f", current)
	}

	if current == 0 {
		return c.Enable(false)
	}

	// Store ORIGINAL request BEFORE clipping (for timer)
	originalPowerRequest := current * c.config.Voltage

	// Ensure minimum current (clipping for miner)
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

	c.mu.Lock()
	currentTarget := c.powerState.LastTarget
	c.mu.Unlock()

	// Handle power changes
	if originalPowerRequest < float64(currentTarget) {
		// Pass BOTH: original (for timer) and clipped (for miner)
		newPowerRequest, err := c.handlePowerDecrease(originalPowerRequest, clippedPowerRequest, currentTarget, wasClipped)
		if err != nil {
			return err
		}
		// If return is 0, turn off miner
		if newPowerRequest == 0 {
			c.log.INFO.Printf("%s: Insufficient solar power - turning off miner", c.hardware.Name)
			return c.Enable(false)
		}
		if newPowerRequest == clippedPowerRequest {
			c.log.DEBUG.Printf("%s: Power unchanged at %.0fW (waiting for timer or maintaining target)",
				c.hardware.Name, clippedPowerRequest)
			return nil // No change needed
		}
		clippedPowerRequest = newPowerRequest
	} else {
		// Power increase - reset decrease tracking
		c.resetDecreaseTracking()
	}

	// Use clipped request for actual power setting
	powerRequest := clippedPowerRequest

	// If power target not enabled, use on/off control
	if !c.powerState.Enabled {
		return c.handleOnOffControl()
	}

	// Calculate target power
	c.mu.Lock()
	isIncreasing := powerRequest > float64(c.powerState.LastTarget)
	c.mu.Unlock()

	targetPowerInt := c.calculateTargetPower(powerRequest, isIncreasing)

	// Check if power changed
	c.mu.Lock()
	powerChanged := targetPowerInt != c.powerState.LastTarget
	c.mu.Unlock()

	if !powerChanged {
		return nil
	}

	// Wait if needed for power increase
	if isIncreasing {
		c.waitForPowerIncreaseInterval()
	}

	// Set new power target
	if err := c.setPowerTarget(targetPowerInt); err != nil {
		return err
	}

	// Ensure miner is enabled
	return c.ensureMinerEnabled()
}

// handleOnOffControl handles miner control when power target is not available
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

// waitForPowerIncreaseInterval waits before allowing power increase
func (c *BraiinsOS) waitForPowerIncreaseInterval() {
	c.mu.Lock()
	timeSinceLastUpdate := time.Since(c.powerState.LastUpdate)
	shouldWait := c.config.PowerTargetInterval > minIntervalForWait &&
		timeSinceLastUpdate < c.config.PowerTargetInterval
	c.mu.Unlock()

	if shouldWait {
		waitTime := c.config.PowerTargetInterval - timeSinceLastUpdate
		c.log.DEBUG.Printf("%s: Waiting %v before power increase",
			c.hardware.Name, waitTime.Round(time.Second))
		time.Sleep(waitTime)
	}
}

// ensureMinerEnabled ensures miner is enabled
func (c *BraiinsOS) ensureMinerEnabled() error {
	enabled, err := c.Enabled()
	if err != nil {
		return err
	}

	if !enabled {
		return c.Enable(true)
	}

	return nil
}

// LoadpointControl registers loadpoint controller interface
func (c *BraiinsOS) LoadpointControl(lp loadpoint.API) {
	c.lp = lp
	c.log.DEBUG.Printf("%s: LoadpointController interface connected", c.hardware.Name)
}

// Verify interface implementations
var _ api.Charger = (*BraiinsOS)(nil)
var _ api.ChargerEx = (*BraiinsOS)(nil)
var _ api.Meter = (*BraiinsOS)(nil)
var _ api.PhaseCurrents = (*BraiinsOS)(nil)
var _ loadpoint.Controller = (*BraiinsOS)(nil)
