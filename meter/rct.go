package meter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/evcc-io/evcc/api"
	"github.com/evcc-io/evcc/util"
	"github.com/mlnoga/rct"
)

/*
This meter supports devices implementing the RCT communication protocol, e.g. the RCT PS 6.0 with / without battery.

** Usages **
The following usages are supported:
- grid    ... for reading the power imported or exported to the grid
- pv      ... for reading the power produced by the pv
- battery ... for reading the power imported or exported to the battery

** Example configuration **
meters:
- name: GridMeter
  type: rct
  uri: 192.168.1.23
  cache: 2s
  usage: grid
- name: PvMeter
  type: rct
  uri: 192.168.1.23
  cache: 2s
  usage: pv
- name: BatteryMeter
  type: rct
  uri: 192.168.1.23
  cache: 2s
  usage: battery
*/

// RCT implements the api.Meter interface
type RCT struct {
	bo    *backoff.ExponentialBackOff
	conn  *rct.Connection // connection with the RCT device
	usage string          // grid, pv, battery
}

func init() {
	registry.Add("rct", NewRCTFromConfig)
}

//go:generate go tool decorate -f decorateRCT -b *RCT -r api.Meter -t "api.MeterEnergy,TotalEnergy,func() (float64, error)" -t "api.Battery,Soc,func() (float64, error)" -t "api.BatteryController,SetBatteryMode,func(api.BatteryMode) error" -t "api.BatteryCapacity,Capacity,func() float64"

// NewRCTFromConfig creates an RCT from generic config
func NewRCTFromConfig(other map[string]interface{}) (api.Meter, error) {
	cc := struct {
		capacity       `mapstructure:",squash"`
		Uri, Usage     string
		MinSoc, MaxSoc int
		Cache          time.Duration
	}{
		Cache: time.Second,
	}

	if err := util.DecodeOther(other, &cc); err != nil {
		return nil, err
	}

	if cc.Usage == "" {
		return nil, errors.New("missing usage")
	}

	return NewRCT(cc.Uri, cc.Usage, cc.MinSoc, cc.MaxSoc, cc.Cache, cc.capacity.Decorator())
}

var rctMu sync.Mutex

// NewRCT creates an RCT meter
func NewRCT(uri, usage string, minSoc, maxSoc int, cache time.Duration, capacity func() float64) (api.Meter, error) {
	rctMu.Lock()
	defer rctMu.Unlock()

	conn, err := rct.NewConnection(uri, cache)
	if err != nil {
		return nil, err
	}

	bo := backoff.NewExponentialBackOff(
		backoff.WithInitialInterval(10*time.Millisecond),
		backoff.WithMaxElapsedTime(time.Second))

	m := &RCT{
		usage: strings.ToLower(usage),
		conn:  conn,
		bo:    bo,
	}

	// decorate api.MeterEnergy
	var totalEnergy func() (float64, error)
	if usage == "grid" {
		totalEnergy = m.totalEnergy
	}

	// decorate api.BatterySoc
	var batterySoc func() (float64, error)
	var batteryMode func(api.BatteryMode) error
	if usage == "battery" {
		batterySoc = m.batterySoc

		batteryMode = func(mode api.BatteryMode) error {
			if mode != api.BatteryNormal {
				batStatus, err := m.queryInt32(rct.BatteryBatStatus)
				if err != nil {
					return err
				}

				// see https://github.com/weltenwort/home-assistant-rct-power-integration/issues/264#issuecomment-2124811644
				if batStatus != 0 {
					return errors.New("invalid battery operating mode")
				}
			}

			switch mode {
			case api.BatteryNormal:
				if err := m.conn.Write(rct.PowerMngSocStrategy, []byte{rct.SOCTargetInternal}); err != nil {
					return err
				}

				if err := m.conn.Write(rct.BatterySoCTargetMin, m.floatVal(float32(minSoc)/100)); err != nil {
					return err
				}

				return m.conn.Write(rct.PowerMngBatteryPowerExternW, m.floatVal(float32(0)))

			case api.BatteryHold:
				if err := m.conn.Write(rct.PowerMngSocStrategy, []byte{rct.SOCTargetInternal}); err != nil {
					return err
				}

				return m.conn.Write(rct.BatterySoCTargetMin, m.floatVal(float32(maxSoc)/100))

			case api.BatteryCharge:
				if err := m.conn.Write(rct.PowerMngUseGridPowerEnable, []byte{1}); err != nil {
					return err
				}

				if err := m.conn.Write(rct.PowerMngBatteryPowerExternW, m.floatVal(float32(-10_000))); err != nil {
					return err
				}

				return m.conn.Write(rct.PowerMngSocStrategy, []byte{rct.SOCTargetExternal})

			default:
				return api.ErrNotAvailable
			}
		}
	}

	return decorateRCT(m, totalEnergy, batterySoc, batteryMode, capacity), nil
}

func (m *RCT) floatVal(f float32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, math.Float32bits(f))
	return data
}

// CurrentPower implements the api.Meter interface
func (m *RCT) CurrentPower() (float64, error) {
	switch m.usage {
	case "grid":
		return m.queryFloat(rct.TotalGridPowerW)

	case "pv":
		a, err := m.queryFloat(rct.SolarGenAPowerW)
		if err != nil {
			return 0, err
		}
		b, err := m.queryFloat(rct.SolarGenBPowerW)
		if err != nil {
			return 0, err
		}
		c, err := m.queryFloat(rct.S0ExternalPowerW)
		return a + b + c, err

	case "battery":
		return m.queryFloat(rct.BatteryPowerW)

	default:
		return 0, fmt.Errorf("invalid usage: %s", m.usage)
	}
}

// totalEnergy implements the api.MeterEnergy interface
func (m *RCT) totalEnergy() (float64, error) {
	switch m.usage {
	case "grid":
		res, err := m.queryFloat(rct.TotalEnergyGridWh)
		return res / 1000, err

	case "pv":
		a, err := m.queryFloat(rct.TotalEnergySolarGenAWh)
		if err != nil {
			return 0, err
		}
		b, err := m.queryFloat(rct.TotalEnergySolarGenBWh)
		return (a + b) / 1000, err

	case "battery":
		in, err := m.queryFloat(rct.TotalEnergyBattInWh)
		if err != nil {
			return 0, err
		}
		out, err := m.queryFloat(rct.TotalEnergyBattOutWh)
		return (in - out) / 1000, err

	default:
		return 0, fmt.Errorf("invalid usage: %s", m.usage)
	}
}

// batterySoc implements the api.Battery interface
func (m *RCT) batterySoc() (float64, error) {
	res, err := m.queryFloat(rct.BatterySoC)
	return res * 100, err
}

// queryFloat adds retry logic of recoverable errors to QueryFloat32
func (m *RCT) queryFloat(id rct.Identifier) (float64, error) {
	m.bo.Reset()

	res, err := backoff.RetryWithData(func() (float32, error) {
		res, err := m.conn.QueryFloat32(id)
		if err != nil && !errors.As(err, new(rct.RecoverableError)) {
			err = backoff.Permanent(err)
		}

		return res, err
	}, m.bo)

	return float64(res), err
}

// queryInt32 adds retry logic of recoverable errors to QueryInt32
func (m *RCT) queryInt32(id rct.Identifier) (int32, error) {
	m.bo.Reset()

	res, err := backoff.RetryWithData(func() (int32, error) {
		res, err := m.conn.QueryInt32(id)
		if err != nil && !errors.As(err, new(rct.RecoverableError)) {
			err = backoff.Permanent(err)
		}

		return res, err
	}, m.bo)

	return res, err
}
