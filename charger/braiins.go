// LICENSE
// Copyright (c) 2025 TobiasHuber1980
// This module is NOT covered by the MIT license. All rights reserved.
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// File: charger/braiins.go
// Native Go implementation for Braiins OS evcc integration
// 
// REQUIREMENTS:
// - Braiins OS with API enabled (default port 80)
// - For dynamic power control: Enable "Power Target" mode in Braiins OS tuner settings
// - Without Power Target: Only on/off control available
//
// Version: 1.3.6 (added API constants + improved HTTP status handling)
// Tested with real API v1.0.0
// https://developer.braiins-os.com/latest/openapi.html

package charger

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/evcc-io/evcc/api"
	"github.com/evcc-io/evcc/util"
	"github.com/evcc-io/evcc/util/request"
)

// Miner status constants
const (
	MinerStatusMining = 2 // Mining active
	MinerStatusPaused = 3 // Mining paused
)

// API endpoints
const (
	apiPathLogin         = "/api/v1/auth/login"
	apiPathMinerDetails  = "/api/v1/miner/details"
	apiPathMinerStats    = "/api/v1/miner/stats"
	apiPathPause         = "/api/v1/actions/pause"
	apiPathResume        = "/api/v1/actions/resume"
	apiPathConstraints   = "/api/v1/configuration/constraints"
	apiPathPerformance   = "/api/v1/performance/mode"
	apiPathPowerTarget   = "/api/v1/performance/power-target"
)

// BraiinsOS charger implementation
type BraiinsOS struct {
	*request.Helper
	*embed
	uri                string
	user               string
	password           string
	token              string
	tokenExpiry        time.Time
	minWatts           int
	defaultWatts       int
	maxWatts           int
	configMaxPower     int
	voltage            float64 // Configurable grid voltage
	powerTargetEnabled bool
	powerTargetWarned  bool // To avoid spam warnings
	log                *util.Logger
}

// BraiinsConfig is the configuration struct
type BraiinsConfig struct {
	URI      string        `mapstructure:"uri"`
	User     string        `mapstructure:"user"`
	Password string        `mapstructure:"password"`
	Timeout  time.Duration `mapstructure:"timeout"`
	MaxPower int           `mapstructure:"maxPower"` // Optional: User-defined power limit
	Voltage  float64       `mapstructure:"voltage"`  // Configurable grid voltage
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

// PerformanceMode structures
type PerformanceMode struct {
	TunerMode struct {
		Target struct {
			PowerTarget struct {
				PowerTarget struct {
					Watt int `json:"watt"`
				} `json:"power_target"`
			} `json:"powertarget"`
		} `json:"target"`
	} `json:"tunermode"`
}

// ConfigConstraints for power limits discovery
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
}

func init() {
	registry.Add("braiins", NewBraiinsFromConfig)
}

// NewBraiinsFromConfig creates a Braiins charger from generic config
func NewBraiinsFromConfig(other map[string]interface{}) (api.Charger, error) {
	var cc BraiinsConfig
	if err := util.DecodeOther(other, &cc); err != nil {
		return nil, err
	}

	// Set defaults
	if cc.Timeout == 0 {
		cc.Timeout = 15 * time.Second
	}
	if cc.User == "" {
		cc.User = "root"
	}
	if cc.Voltage == 0 {
		cc.Voltage = 230.0 // Default: Europe standard
	}

	uri := fmt.Sprintf("http://%s", cc.URI)
	return NewBraiins(uri, cc.User, cc.Password, cc.Timeout, cc.MaxPower, cc.Voltage)
}

// NewBraiins creates Braiins charger
func NewBraiins(uri, user, password string, timeout time.Duration, maxPower int, voltage float64) (api.Charger, error) {
	log := util.NewLogger("braiins")

	c := &BraiinsOS{
		Helper:         request.NewHelper(log),
		embed: &embed{
			Icon_:     "generic",
			Features_: []api.Feature{api.IntegratedDevice},
		},
		log:            log,
		uri:            uri,
		user:           user,
		password:       password,
		configMaxPower: maxPower,
		voltage:        voltage,
	}

	c.Client.Timeout = timeout

	// Test connection and get initial token
	if err := c.login(); err != nil {
		c.log.ERROR.Printf("Connection test failed: %v", err)
		return nil, fmt.Errorf("connection test failed: %w", err)
	}

	// Discover miner constraints - REQUIRED for power control
	if err := c.discoverConstraints(); err != nil {
		c.log.ERROR.Printf("Failed to get miner constraints: %v", err)
		return nil, fmt.Errorf("failed to get miner constraints: %w", err)
	}

	// Check if miner supports power target mode
	if err := c.detectPowerTargetMode(); err != nil {
		c.log.WARN.Printf("Power target mode detection failed - using on/off control")
		c.powerTargetEnabled = false
	}

	// Log configuration summary
	effectiveMax := c.getEffectiveMaxPower()
	if c.powerTargetEnabled {
		c.log.INFO.Printf("Braiins miner ready at %s with power control (range: %d-%dW, max: %dW, %.0fV)", 
			uri, c.minWatts, c.maxWatts, effectiveMax, c.voltage)
	} else {
		c.log.INFO.Printf("Braiins miner ready at %s with on/off control (%.0fV)", uri, c.voltage)
	}

	return c, nil
}

// login gets a new authentication token
func (c *BraiinsOS) login() error {
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
		c.log.ERROR.Printf("Login request failed: %v", err)
		return fmt.Errorf("login request failed: %w", err)
	}

	if resp.Token == "" {
		c.log.ERROR.Printf("Login succeeded, but no token was received.")
		return fmt.Errorf("no token received")
	}

	c.token = resp.Token

	// Set token expiry with safety buffer
	tokenTimeout := time.Duration(resp.TimeoutS) * time.Second
	if tokenTimeout <= 0 {
		tokenTimeout = 1 * time.Hour
	}
	if tokenTimeout > 30*time.Second {
		c.tokenExpiry = time.Now().Add(tokenTimeout - 30*time.Second)
	} else {
		c.tokenExpiry = time.Now().Add(tokenTimeout)
	}

	c.log.DEBUG.Printf("Login successful, token expires in %s", tokenTimeout)
	return nil
}

// makeAuthRequest creates and executes an authenticated HTTP request
func (c *BraiinsOS) makeAuthRequest(method, path string, body any) (*http.Response, error) {
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

	req.Header.Set("Authorization", c.token)
	return c.Do(req)
}

// authRequest makes an authenticated request without body
func (c *BraiinsOS) authRequest(method, path string) (*http.Response, error) {
	return c.makeAuthRequest(method, path, nil)
}

// authRequestWithBody makes an authenticated request with JSON body
func (c *BraiinsOS) authRequestWithBody(method, path string, body any) (*http.Response, error) {
	return c.makeAuthRequest(method, path, body)
}

// closeResponseBody safely closes response body with error logging
func (c *BraiinsOS) closeResponseBody(resp *http.Response) {
	if err := resp.Body.Close(); err != nil {
		c.log.DEBUG.Printf("Failed to close response body: %v", err)
	}
}

// discoverConstraints gets miner power limits from API
func (c *BraiinsOS) discoverConstraints() error {
	resp, err := c.authRequest(http.MethodGet, apiPathConstraints)
	if err != nil {
		return fmt.Errorf("constraints request failed: %w", err)
	}
	defer c.closeResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("constraints request failed: %s (HTTP %d)", resp.Status, resp.StatusCode)
	}

	var constraints ConfigConstraints
	if err := json.NewDecoder(resp.Body).Decode(&constraints); err != nil {
		return fmt.Errorf("failed to decode constraints: %w", err)
	}

	c.minWatts = constraints.TunerConstraints.PowerTarget.Min.Watt
	c.defaultWatts = constraints.TunerConstraints.PowerTarget.Default.Watt
	c.maxWatts = constraints.TunerConstraints.PowerTarget.Max.Watt

	c.log.DEBUG.Printf("Discovered power constraints: min=%dW, default=%dW, max=%dW",
		c.minWatts, c.defaultWatts, c.maxWatts)

	return nil
}

// detectPowerTargetMode checks if miner supports power target mode
func (c *BraiinsOS) detectPowerTargetMode() error {
	resp, err := c.authRequest(http.MethodGet, apiPathPerformance)
	if err != nil {
		return fmt.Errorf("performance mode request failed: %w", err)
	}
	defer c.closeResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("performance mode request failed: %s (HTTP %d)", resp.Status, resp.StatusCode)
	}

	var mode PerformanceMode
	if err := json.NewDecoder(resp.Body).Decode(&mode); err != nil {
		return fmt.Errorf("failed to decode performance mode: %w", err)
	}

	// Fixed: Check if power target mode is available, not if value is already set
	// If the API returns the powertarget structure, the mode is supported
	// evcc will set the actual power values dynamically
	c.powerTargetEnabled = true

	c.log.DEBUG.Printf("Power target mode enabled: %v", c.powerTargetEnabled)
	return nil
}

// getEffectiveMaxPower returns the effective maximum power for evcc control
func (c *BraiinsOS) getEffectiveMaxPower() int {
	// Default to miner's reported default power
	effectiveMax := c.defaultWatts

	// Use user-configured value if provided
	if c.configMaxPower > 0 {
		effectiveMax = c.configMaxPower
	}

	// Constrain to hardware limits
	effectiveMax = int(math.Min(float64(effectiveMax), float64(c.maxWatts)))
	effectiveMax = int(math.Max(float64(effectiveMax), float64(c.minWatts)))

	return effectiveMax
}

// getMinerStatus gets the current miner status from API
func (c *BraiinsOS) getMinerStatus() (int, error) {
	resp, err := c.authRequest(http.MethodGet, apiPathMinerDetails)
	if err != nil {
		return 0, fmt.Errorf("miner details request failed: %w", err)
	}
	defer c.closeResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("miner details failed: %s (HTTP %d)", resp.Status, resp.StatusCode)
	}

	var details MinerDetails
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		return 0, fmt.Errorf("failed to decode miner details: %w", err)
	}

	return details.Status, nil
}

// setPowerTarget sets the miner power target
func (c *BraiinsOS) setPowerTarget(targetWatts int) error {
	resp, err := c.authRequestWithBody(http.MethodPut, apiPathPowerTarget, PowerTarget{Watt: targetWatts})
	if err != nil {
		return fmt.Errorf("set power target failed: %w", err)
	}
	defer c.closeResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("set power target failed: %s (HTTP %d)", resp.Status, resp.StatusCode)
	}

	c.log.DEBUG.Printf("Power target set to %dW", targetWatts)
	return nil
}

// Status implements the api.Charger interface
func (c *BraiinsOS) Status() (api.ChargeStatus, error) {
	status, err := c.getMinerStatus()
	if err != nil {
		return api.StatusNone, err
	}

	// Use named constants for better readability
	switch status {
	case MinerStatusMining:
		return api.StatusC, nil // Mining active
	case MinerStatusPaused:
		return api.StatusB, nil // Mining paused
	default:
		return api.StatusNone, nil // Unknown status
	}
}

// Enabled implements the api.Charger interface
func (c *BraiinsOS) Enabled() (bool, error) {
	status, err := c.getMinerStatus()
	if err != nil {
		return false, err
	}
	// Enabled when mining OR paused (both are functional states)
	return status == MinerStatusMining || status == MinerStatusPaused, nil
}

// Enable implements the api.Charger interface
func (c *BraiinsOS) Enable(enable bool) error {
	endpoint := apiPathPause
	action := "paused"
	if enable {
		endpoint = apiPathResume
		action = "resumed"
	}

	resp, err := c.authRequest(http.MethodPut, endpoint)
	if err != nil {
		return err
	}
	defer c.closeResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enable/disable failed: %s (HTTP %d)", resp.Status, resp.StatusCode)
	}

	c.log.DEBUG.Printf("Miner %s", action)

	return nil
}

// MaxCurrent implements the api.Charger interface with configurable voltage
func (c *BraiinsOS) MaxCurrent(current int64) error {
	if current == 0 {
		return c.Enable(false) // Pause mining
	}

	// Calculate desired power based on current amperage and configured voltage
	powerRequest := float64(current) * c.voltage

	// Check if requested power meets minimum hardware requirements for PV surplus operation
	if powerRequest < float64(c.minWatts) {
		c.log.DEBUG.Printf("Requested %.1fA (%.0fW) insufficient for hardware minimum (%dW) - keeping miner paused", 
			float64(current), powerRequest, c.minWatts)
		return c.Enable(false) // Pause - insufficient PV surplus for hardware minimum
	}

	// Enough PV surplus available - start miner
	if err := c.Enable(true); err != nil {
		return err
	}

	// Graceful fallback for miners not in power target mode
	if !c.powerTargetEnabled {
		// Only warn once to avoid spam
		if !c.powerTargetWarned {
			c.log.WARN.Printf("Enable Power Target in Braiins OS for dynamic power control")
			c.powerTargetWarned = true
		}
		return nil // Simple on/off, no power control
	}

	effectiveMax := c.getEffectiveMaxPower()
	if effectiveMax <= c.minWatts {
		c.log.WARN.Printf("Effective max power (%dW) too low for dynamic control - using minimum (%dW)", effectiveMax, c.minWatts)
		return c.setPowerTarget(c.minWatts)
	}

	// Apply power limits with explicit rounding
	targetPower := math.Max(float64(c.minWatts), powerRequest)
	targetPower = math.Min(float64(effectiveMax), targetPower)

	c.log.DEBUG.Printf("Requested %.1fA at %.0fV, setting power target to %.0fW", 
		float64(current), c.voltage, targetPower)

	return c.setPowerTarget(int(math.Round(targetPower)))
}

// CurrentPower implements the api.Meter interface
func (c *BraiinsOS) CurrentPower() (float64, error) {
	resp, err := c.authRequest(http.MethodGet, "/api/v1/miner/stats")
	if err != nil {
		return 0, fmt.Errorf("stats request failed: %w", err)
	}
	defer c.closeResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("stats failed: %s (HTTP %d)", resp.Status, resp.StatusCode)
	}

	var stats MinerStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return 0, fmt.Errorf("failed to decode miner stats: %w", err)
	}

	power := float64(stats.PowerStats.ApproximatedConsumption.Watt)
	c.log.DEBUG.Printf("Current power consumption: %.0fW", power)

	return power, nil
}

// Currents implements the api.PhaseCurrents interface with configurable voltage
func (c *BraiinsOS) Currents() (float64, float64, float64, error) {
	power, err := c.CurrentPower()
	if err != nil {
		return 0, 0, 0, err
	}

	// Calculate current using configured voltage
	current := power / c.voltage
	return current, 0, 0, nil
}

// Interface compliance checks
var _ api.Charger = (*BraiinsOS)(nil)
var _ api.Meter = (*BraiinsOS)(nil)
var _ api.PhaseCurrents = (*BraiinsOS)(nil)