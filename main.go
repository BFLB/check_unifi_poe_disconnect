// Copyright (c) 2019 Bernhard Fluehmann. All rights reserved.
// Use of this source code is governed by ISC-style license
// that can be found in the LICENSE file.

// Nagios check for poe disconnect events
// Mainly used to protect public facing AP ports
// Optionally provision (block) affected ports

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	checker "github.com/BFLB/monitoringplugin"
	p "github.com/BFLB/monitoringplugin/performancedata"
	r "github.com/BFLB/monitoringplugin/range"
	"github.com/BFLB/monitoringplugin/status"
	activeWriter "github.com/BFLB/monitoringplugin/writers/activeWriter"
	"github.com/BFLB/unifi"
)

const VERSION = "v0.2"

var (
	host              = flag.String("host", "", "Controller hostname")
	port              = flag.String("port", "8443", "Controller port")
	site              = flag.String("site", "default", "Site ID or name, UniFi v3 and later")
	user              = flag.String("user", "", "Controller username")
	pass              = flag.String("pass", "", "Controller password")
	path              = flag.String("path", "", "Path of output file")
	version           = flag.Int("version", 5, "Controller base version")
	warning           = flag.String("warning", "7", "Execution Time(s) warning threshold")
	critical          = flag.String("critical", "10", "Execution Time(s) critical threshold")
	profileBlock      = flag.String("profileBlock", "", "If set, affected ports will be set to the given port profile, e.g. disabled")
	profileCurr       = flag.String("profileCurr", "", "Check only applies to ports of given port profile. Only non default profiles allowed")
	portNameBlock     = flag.String("portNameBlock", "", "Set port name after blocking")
	portNameCurr      = flag.String("portNameCurr", "", "Set port name after reset (set back to curr)")
	perfdata          = flag.Bool("perfdata", false, "Add perfdata")
	eventFilterLimit  = flag.Int("eventFilterLimit", 3000, "Maximum  number of alert events to be fetched")
	eventFilterStart  = flag.Int("eventFilterStart", 0, "At witch alarm event to start fetching")
	eventFilterWithin = flag.Int("eventFilterWithin", 24, "How many hours back to be fetched")
	v                 = flag.Bool("V", false, "Version")
)

// Counter struct used for extit message
type counters struct {
	events             int
	provisionedBlock   int
	provisionedUnblock int
	blocked            int
	unblocked          int
	failed             int
}

func main() {

	// Timestamp to calculate execution time
	timestampStart := time.Now()

	// Counters
	counters := counters{}

	// Create check
	check := checker.New()

	// Check-message
	message := ""

	// Create writer
	writer := activeWriter.New()

	// Parse command-line args
	flag.Parse()

	// Version information
	if *v {
		message = fmt.Sprintf("Version: check=%s, monitoring-library:%s", VERSION, checker.VERSION)
		check.Status.Unknown()
		check.Message(message)
		writer.Write(check)
	}

	// Check mandatory args
	if *host == "" {
		flag.Usage()
	}
	if *user == "" {
		flag.Usage()
	}
	if *pass == "" {
		flag.Usage()
	}
	if *profileCurr == "" {
		flag.Usage()
	}
	// Catch not allowed profile settings
	switch strings.ToLower(*profileCurr) {
	case "", "all", "disabled":
		flag.Usage()
	}

	// Set ranges (monitoring) TODO: Move down
	var rangeExecWarn *r.Range
	var rangeExecCrit *r.Range

	if *warning != "" {
		rangeExecWarn = r.New()
		rangeExecWarn.Parse(*warning)
	}
	if *critical != "" {
		rangeExecCrit = r.New()
		rangeExecCrit.Parse(*critical)
	}

	// Login to UniFi controller
	u, err := unifi.Login(*user, *pass, *host, *port, *site, *version)
	if err != nil {
		message = fmt.Sprintf("Login error:%s", err.Error())
		check.Status.Unknown()
		check.Message(message)
		writer.Write(check)
	}
	defer u.Logout()

	// Get site
	site, err := u.Site(*site)
	if err != nil {
		log.Fatal(err)
	}

	// Get current port-profile
	currProfile, err := u.PortProfile(site, *profileCurr)
	if err != nil {
		message = fmt.Sprintf("Port-profile not found:%s", err.Error())
		check.Status.Unknown()
		check.Message(message)
		writer.Write(check)
	}

	// Get block port-profile (optional)
	var blockProfile *unifi.PortProfile
	if *profileBlock == "" {
		blockProfile = nil
	} else {
		blockProfile, err = u.PortProfile(site, *profileBlock)
		if err != nil {
			message = fmt.Sprintf("Port-profile not found:%s", err.Error())
			check.Status.Unknown()
			check.Message(message)
			writer.Write(check)
		}
	}

	// Set event filters
	var eventFilter unifi.EventFilter
	// TODO: Add flags
	eventFilter.Limit = *eventFilterLimit
	eventFilter.Start = *eventFilterStart
	eventFilter.Within = *eventFilterWithin

	// Get a slice of raw events
	rawAlarms, err := u.RawAlarms(site, eventFilter)
	if err != nil {
		log.Fatalln(err)
		return
	}

	// Get a slice of poe events
	events, err := poeEvents(rawAlarms)

	for _, event := range events {
		do(u, site, event, currProfile, blockProfile, *portNameCurr, *portNameBlock, &counters)
		if err != nil {
			counters.failed += 1
		}
	}

	tExec := time.Now().Sub(timestampStart).Seconds()
	// HACK: Better way to do it?
	// Round to 3 digits
	tExecRounded := fmt.Sprintf("%.3f", tExec)
	tExec, _ = strconv.ParseFloat(tExecRounded, 64)

	// Add message
	message = fmt.Sprintf("%d active matching alerts, %d ports blocked (%d provisioned-block, %d provisioned-unblock, %d failed, EcecTime %f)", counters.events, counters.blocked, counters.provisionedBlock, counters.provisionedUnblock, counters.failed, tExec)
	check.Message(message)

	// Set ranges for Executiontime warning and critical
	rangeWarn := r.New()
	rangeWarn.Parse(*warning)
	rangeCrit := r.New()
	rangeCrit.Parse(*critical)

	// Add performance data
	if *perfdata {
		dataObj, _ := p.New("ActMatchAlerts", float64(counters.events), "", nil, r.New(), nil, nil)
		check.Perfdata(dataObj)

		dataObj, _ = p.New("PortsBlocked", float64(counters.blocked), "", r.New(), nil, nil, nil)
		check.Perfdata(dataObj)

		dataObj, _ = p.New("ProvBlocked", float64(counters.provisionedBlock), "", nil, nil, nil, nil)
		check.Perfdata(dataObj)

		dataObj, _ = p.New("ProvUnblocked", float64(counters.provisionedBlock), "", nil, nil, nil, nil)
		check.Perfdata(dataObj)

		dataObj, _ = p.New("Failed", float64(counters.failed), "", nil, r.New(), nil, nil)
		check.Perfdata(dataObj)

		dataObj, _ = p.New("ExecTime", tExec, "s", rangeWarn, rangeCrit, nil, nil)
		check.Perfdata(dataObj)

	}

	// Everything done. Setup return values and quit
	// Set Status
	// New Status (OK)
	status := status.New()

	// Status Events (Critical if > 0)
	status.Threshold(float64(counters.events), nil, r.New(), false)

	// Status Failed (Critical if > 0)
	status.Threshold(float64(counters.failed), nil, r.New(), false)

	// Status blocked (Warning if > 0)
	status.Threshold(float64(counters.blocked), r.New(), nil, false)

	// Status Executiontime (Warning if > warning, Critical if > critical)
	status.Threshold(tExec, rangeWarn, rangeCrit, false)

	// Assign Status to check
	check.Status = status

	// Write results
	writer.Write(check)

}

// Gets the switch and port and checks if the configured profile belongs to the check.
// Adds coniguration changes to the port depending of command arguments
func do(u *unifi.Unifi, site *unifi.Site, event unifi.EVT_SW_PoeDisconnect, currProfile *unifi.PortProfile, blockProfile *unifi.PortProfile, currPortName string, blockPortName string, c *counters) error {

	// Get the switch
	usw, err := u.USW(site, event.SwName)
	if err != nil {
		return err
	}

	// Get port-overrides (non default settings)
	overrides := usw.PortOverrides

	// Find the port
	for i := range usw.PortOverrides {
		if overrides[i].PortIdx == event.Port {
			// Active (non archived) event
			if archived(event) == false {
				// Check if port belongs current profile matches
				if overrides[i].PortconfID == currProfile.ID {
					c.events += 1
					// Check if must be blocked
					if blockProfile != nil {
						// Change settings (block)
						overrides[i].PortconfID = blockProfile.ID
						if blockPortName != "" {
							overrides[i].Name = blockPortName
						}
						u.SetPortoverrides(site, usw.DeviceID, overrides)
						c.provisionedBlock += 1
					}
				} else { // Check if port already blocked
					if overrides[i].PortconfID == blockProfile.ID {
						c.events += 1
						c.blocked += 1
					}
				}
			} else { // Archived event
				// Check if port belongs to blocked profile
				if blockProfile != nil {
					if overrides[i].PortconfID == blockProfile.ID {
						c.blocked += 1
						// Change settings (unblock)
						overrides[i].PortconfID = currProfile.ID
						if currPortName != "" {
							overrides[i].Name = currPortName
						}
						u.SetPortoverrides(site, usw.DeviceID, overrides)
						c.provisionedUnblock += 1
					}
				}
			}
			break
		}
	}
	return nil
}

// Returns a slice with poeEvents. One per switch/port combination. Non-Archived wins.
func poeEvents(rawEvents []unifi.RawAlarm) ([]unifi.EVT_SW_PoeDisconnect, error) {
	var poeEvents []unifi.EVT_SW_PoeDisconnect
	for _, rawEvent := range rawEvents {

		switch rawEvent.Key {
		case "EVT_SW_PoeDisconnect":
			// Unmarshal rawEvent to poeEvent
			var e unifi.EVT_SW_PoeDisconnect
			err := json.Unmarshal(rawEvent.Data, &e)
			if err != nil {
				return poeEvents, err
			}

			// Avoid duplicates
			if len(poeEvents) == 0 {
				poeEvents = append(poeEvents, e)
			} else {
				var found bool
				found = false
				for _, poeEvent := range poeEvents {
					if poeEvent.SwName == e.SwName && poeEvent.Port == e.Port {
						found = true
						// Override archived
						if e.Archived == nil {
							poeEvent.Archived = nil
							break
						} else if *e.Archived == false {
							*poeEvent.Archived = false
							break
						}
					}
				}
				// New event
				if found == false {
					poeEvents = append(poeEvents, e)
				}
			}
		}
	}
	return poeEvents, nil
}

// Check if event is archived
func archived(event unifi.EVT_SW_PoeDisconnect) bool {
	if event.Archived == nil {
		return false
	}
	return *event.Archived
}
