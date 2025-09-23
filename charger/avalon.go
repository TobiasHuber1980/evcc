package charger

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/evcc-io/evcc/api"
	"github.com/evcc-io/evcc/util"
)

func init() {
	registry.Add("avalon", NewAvalonMinerFromConfig)
}

type AvalonMiner struct {
	log         *util.Logger
	uri         string
	port        string
	voltage     float64
	currentMode int

	psRegex *regexp.Regexp

	ecoMode      AvalonMode
	standardMode AvalonMode
	superMode    AvalonMode
}

type AvalonMode struct {
	Name       string
	Mode       int
	Power      float64
	Hashrate   float64
	Efficiency float64
}

type AvalonMinerConfig struct {
	URI     string  `mapstructure:"uri"`
	Port    string  `mapstructure:"port"`
	Voltage float64 `mapstructure:"voltage"`
}

func NewAvalonMinerFromConfig(other map[string]interface{}) (api.Charger, error) {
	var cc AvalonMinerConfig
	if err := util.DecodeOther(other, &cc); err != nil {
		return nil, err
	}

	return NewAvalonMiner(cc.URI, cc.Port, cc.Voltage)
}

func NewAvalonMiner(uri, port string, voltage float64) (api.Charger, error) {
	if port == "" {
		port = "4028"
	}

	if voltage == 0 {
		voltage = 230
	}

	c := &AvalonMiner{
		log:         util.NewLogger("avalon"),
		uri:         uri,
		port:        port,
		voltage:     voltage,
		currentMode: -1,

		psRegex: regexp.MustCompile(`PS\[([^\]]+)\]`),

		ecoMode: AvalonMode{
			Name:       "Eco",
			Mode:       0,
			Power:      843,
			Hashrate:   54.19,
			Efficiency: 15.5,
		},
		standardMode: AvalonMode{
			Name:       "Standard",
			Mode:       1,
			Power:      1403,
			Hashrate:   80.71,
			Efficiency: 17.3,
		},
		superMode: AvalonMode{
			Name:       "Super",
			Mode:       2,
			Power:      1674,
			Hashrate:   90.0,
			Efficiency: 18.6,
		},
	}

	if _, err := c.sendCommand("version"); err != nil {
		return nil, fmt.Errorf("avalon connection failed: %w", err)
	}

	return c, nil
}

func (c *AvalonMiner) sendCommand(command string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", c.uri, c.port), 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(command))
	if err != nil {
		return "", fmt.Errorf("failed to send command: %w", err)
	}

	var response strings.Builder
	buf := make([]byte, 1024)

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			response.Write(buf[:n])
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			return "", fmt.Errorf("failed to read response: %w", err)
		}

		responseStr := response.String()
		if strings.HasSuffix(responseStr, "|") {
			break
		}
	}

	return response.String(), nil
}

func (c *AvalonMiner) Status() (api.ChargeStatus, error) {
	response, err := c.sendCommand("summary")
	if err != nil {
		return api.StatusNone, err
	}

	if strings.Contains(response, "MHS av=") && !strings.Contains(response, "MHS av=0") {
		return api.StatusC, nil
	}

	return api.StatusA, nil
}

func (c *AvalonMiner) getCurrentPower() (float64, error) {
	response, err := c.sendCommand("estats")
	if err != nil {
		return 0, err
	}

	matches := c.psRegex.FindStringSubmatch(response)
	if len(matches) < 2 {
		return 0, fmt.Errorf("PS values not found in response")
	}

	psValuesStr := strings.TrimSpace(matches[1])
	psValues := strings.Fields(psValuesStr)

	if len(psValues) == 0 {
		return 0, fmt.Errorf("no PS values found")
	}

	powerStr := psValues[len(psValues)-1]
	power, err := strconv.ParseFloat(powerStr, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse power value '%s': %w", powerStr, err)
	}

	if power < 0 || power > 2000 {
		c.log.WARN.Printf("Unusual power reading: %.0fW (expected 0-2000W)", power)
	}

	c.log.DEBUG.Printf("Current power consumption: %.0fW (parsed from PS values: %v)",
		power, psValues)
	return power, nil
}

func (c *AvalonMiner) Enabled() (bool, error) {
	status, err := c.Status()
	if err != nil {
		return false, err
	}
	return status == api.StatusC, nil
}

func (c *AvalonMiner) Enable(enable bool) error {
	if enable {
		cmd := fmt.Sprintf("ascset|0,softon,1:%d", time.Now().Unix()+5)
		_, err := c.sendCommand(cmd)
		if err != nil {
			return fmt.Errorf("failed to enable miner: %w", err)
		}
		c.log.INFO.Printf("Miner enabled (wake up)")
	} else {
		cmd := fmt.Sprintf("ascset|0,softoff,1:%d", time.Now().Unix()+5)
		_, err := c.sendCommand(cmd)
		if err != nil {
			return fmt.Errorf("failed to disable miner: %w", err)
		}
		c.log.INFO.Printf("Miner disabled (standby)")
	}

	return nil
}

func (c *AvalonMiner) setWorkmode(mode int) error {
	cmd := fmt.Sprintf("ascset|0,workmode,set,%d", mode)
	_, err := c.sendCommand(cmd)
	if err != nil {
		return fmt.Errorf("failed to set workmode %d: %w", mode, err)
	}

	var modeName string
	switch mode {
	case 0:
		modeName = "Eco"
	case 1:
		modeName = "Standard"
	case 2:
		modeName = "Super"
	default:
		modeName = "Unknown"
	}

	c.log.INFO.Printf("Workmode set to %s (%d)", modeName, mode)
	return nil
}

func (c *AvalonMiner) getModeForPower(targetPower float64) AvalonMode {
	ecoThreshold := (c.ecoMode.Power + c.standardMode.Power) / 2
	standardThreshold := (c.standardMode.Power + c.superMode.Power) / 2

	if targetPower <= ecoThreshold {
		return c.ecoMode
	} else if targetPower <= standardThreshold {
		return c.standardMode
	} else {
		return c.superMode
	}
}

func (c *AvalonMiner) MaxCurrent(power int64) error {
	return nil
}

func (c *AvalonMiner) SetCurrent(current float64) error {
	if current == 0 {
		c.log.DEBUG.Printf("Current=0A - setting miner to standby")
		c.currentMode = -1
		return c.Enable(false)
	}

	targetPower := current * c.voltage
	selectedMode := c.getModeForPower(targetPower)

	c.log.INFO.Printf("Target: %.0fW (%.2fA) -> %s mode (%.0fW)",
		targetPower, current, selectedMode.Name, selectedMode.Power)

	if err := c.Enable(true); err != nil {
		return fmt.Errorf("failed to enable miner: %w", err)
	}

	if c.currentMode != selectedMode.Mode {
		c.log.DEBUG.Printf("Changing workmode from %d to %d (%s)",
			c.currentMode, selectedMode.Mode, selectedMode.Name)

		if err := c.setWorkmode(selectedMode.Mode); err != nil {
			return fmt.Errorf("failed to set workmode: %w", err)
		}

		c.currentMode = selectedMode.Mode
		c.log.INFO.Printf("Workmode successfully changed to %s", selectedMode.Name)
	} else {
		c.log.DEBUG.Printf("Workmode already set to %s (%d) - skipping",
			selectedMode.Name, selectedMode.Mode)
	}

	return nil
}

func (c *AvalonMiner) GetMinCurrent() float64 {
	return c.ecoMode.Power / c.voltage
}

func (c *AvalonMiner) GetMaxCurrent() float64 {
	return c.superMode.Power / c.voltage
}

func (c *AvalonMiner) GetMaxPower() float64 {
	return c.superMode.Power
}

func (c *AvalonMiner) CurrentPower() (float64, error) {
	return c.getCurrentPower()
}

func (c *AvalonMiner) MaxCurrentMillis() (float64, error) {
	maxCurrent := c.GetMaxCurrent()
	return maxCurrent * 1000, nil
}

func (c *AvalonMiner) Icon() string {
	return "generic"
}

func (c *AvalonMiner) Features() []api.Feature {
	return []api.Feature{api.IntegratedDevice}
}

var _ api.Charger = (*AvalonMiner)(nil)
var _ api.Meter = (*AvalonMiner)(nil)
var _ api.CurrentController = (*AvalonMiner)(nil)
var _ api.IconDescriber = (*AvalonMiner)(nil)
var _ api.FeatureDescriber = (*AvalonMiner)(nil)
