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
	"os"
	"text/tabwriter"

	checker "github.com/BFLB/monitoringplugin"
	r "github.com/BFLB/monitoringplugin/range"
	"github.com/BFLB/monitoringplugin/status"
	activeWriter "github.com/BFLB/monitoringplugin/writers/activeWriter"
	"github.com/BFLB/unifi"
)

const VERSION = "v0.1"

var (
	host          = flag.String("host", "", "Controller hostname")
	port          = flag.String("port", "8443", "Controller port")
	site          = flag.String("site", "default", "Site ID or name, UniFi v3 and later")
	user          = flag.String("user", "", "Controller username")
	pass          = flag.String("pass", "", "Controller password")
	path          = flag.String("path", "", "Path of output file")
	version       = flag.Int("version", 5, "Controller base version")
	warning       = flag.String("warning", "7", "Execution Time(s) warning threshold")
	critical      = flag.String("critical", "10", "Execution Time(s) critical threshold")
	profileBlock  = flag.String("profileBlock", "", "If set, affected ports will be set to the given port profile, e.g. disabled")
	profileCurr   = flag.String("profileCurr", "all", "Check only applies to ports of given port profile")
	portNameBlock = flag.String("portNameBlock", "", "Set port name after blocking")
	portNameCurr  = flag.String("portNameCurr", "", "Set port name after reset (set back to curr)")
	v             = flag.Bool("V", false, "Version")
)

type counters struct {
	events           int
	archived         int
	portsProvisioned int
	portsBlocked     int
	portsUnblocked   int
	skipped          int
	failed           int
}

func main() {
	// TODO: Remove
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 3, ' ', 0)
	defer w.Flush()

	// counters (Used for check-result)
	counters := counters{}

	// Create new check
	check := checker.New()
	message := ""

	// Create writer
	writer := activeWriter.New()

	// Fixme
	// Print usage info (Override of flag.Usage)
	/*flag.Usage = func() {
		check.Message("Usage:")
		check.Message("    host: Controller hostname (mandatory)")
		check.Message("    port: Controller port (optional")
		check.Message("    site: Site ID or name, UniFi v3 and later (optional)")
		check.Message("    username: Controller username (mandatory)")
		check.Message("    password: Controller password (mandatory)")
		check.Message("    path: Path of output file (optional)")
		check.Message("    version: Controller base version (Optional)")
		check.Message("    warning: Execution Time(s) warning threshold (Optional)")
		check.Message("    critical: Execution Time(s) critical threshold (Optional)")
		check.Message("    currentProfile: Check only applies to ports of given port profile (Optional)")
		check.Message("    blockProfile: If set, affected ports will be set to the given port profile, e.g. disabled (Optional)")
		check.Message("    alias: Set port alias (optional)")
		check.Message("    V: Version (optional)")
		check.Status.Unknown()
		writer.Write(check)
	}*/

	// Parse command-line args
	flag.Parse()

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

	// Set ranges
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

	// Select site
	site, err := u.Site(*site)
	if err != nil {
		log.Fatal(err)
	}

	// Get port-profiles
	currProfile, err := u.PortProfile(site, *profileCurr)
	if err != nil {
		message = fmt.Sprintf("Port-profile not found:%s", err.Error())
		check.Status.Unknown()
		check.Message(message)
		writer.Write(check)
	}
	blockProfile, err := u.PortProfile(site, *profileBlock)
	if err != nil {
		message = fmt.Sprintf("Port-profile not found:%s", err.Error())
		check.Status.Unknown()
		check.Message(message)
		writer.Write(check)
	}

	// Set event filters
	var eventFilter unifi.EventFilter
	// TODO: Add flags
	eventFilter.Limit = 3000
	eventFilter.Start = 0
	eventFilter.Within = 24

	// Get a slice of raw events
	rawEvents, err := u.RawAlarms(site, eventFilter)
	if err != nil {
		log.Fatalln(err)
		return
	}

	// Get a slice of poe events
	// TODO: Only events which are not acknowledged
	var poeEvents []unifi.EVT_SW_PoeDisconnect
	for _, rawEvent := range rawEvents {

		switch rawEvent.Key {
		case "EVT_SW_PoeDisconnect":

			var e unifi.EVT_SW_PoeDisconnect
			err := json.Unmarshal(rawEvent.Data, &e)
			if err == nil {
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
						// New event
						if found == false {
							poeEvents = append(poeEvents, e)
						}
					}
				}
			}
		}
	}

	for _, poeEvent := range poeEvents {

		// Is Alert Archived?
		var archived bool
		if poeEvent.Archived != nil {
			if *poeEvent.Archived {
				archived = true
			} else {
				archived = false
			}
		}

		// Check if profile matches
		match, err := matchProfile(u, site, poeEvent, currProfile, &counters)
		if err != nil {
			counters.failed += 1
		}
		if match == false {
			match, err = matchProfile(u, site, poeEvent, blockProfile, &counters)
			if err != nil {
				counters.failed += 1
			}
		}
		if match == true {

			//Check if port is already blocked
			blocked, _ := portBlocked(u, site, poeEvent, blockProfile, &counters)

			// If event not archived, block port
			if archived == false {
				fmt.Println("Archived false")
				if blocked == false {
					fmt.Println("Blocked false")
					err = configurePort(u, site, poeEvent, currProfile, blockProfile, *portNameBlock, &counters)
					if err != nil {
						counters.failed += 1
					}
				}
			} else {
				fmt.Println("Archived true")
				// Event archived. If port still blocked, unblock it
				if blocked {
					err = configurePort(u, site, poeEvent, blockProfile, currProfile, *portNameCurr, &counters)
					if err != nil {
						counters.failed += 1
					}
				}
			}
		}
	}

	// Everything done. Setup return values and quit
	// Set status TODO: Comment
	status := status.New()
	if counters.events > 0 {
		status.Critical(false)
	}
	if counters.failed > 0 {
		status.Critical(false)
	}
	if counters.portsBlocked > 0 {
		status.Warning(false)
	}
	status.Ok(false)
	check.Status = status

	// Add message
	message = fmt.Sprintf("%d matching events, %d ports blocked (%d provisioned, %d failed)", counters.events, counters.portsBlocked, counters.portsProvisioned, counters.failed)
	check.Message(message)

	// TODO Add performance data

	// Write results
	writer.Write(check)

}

func configurePort(u *unifi.Unifi, site *unifi.Site, event unifi.EVT_SW_PoeDisconnect, currProfile *unifi.PortProfile, newProfile *unifi.PortProfile, newPortName string, c *counters) error {

	// Get the switch
	usw, err := u.USW(site, event.SwName)
	if err != nil {
		return err
	}

	// Get port-overrides (non default settings)
	overrides := usw.PortOverrides

	// Get the port
	for i := range usw.PortOverrides {
		if overrides[i].PortIdx == event.Port {
			// Check if belongs to current profile
			if overrides[i].PortconfID == currProfile.ID {

				// If new profile available, configure it
				if newProfile != nil {
					overrides[i].PortconfID = newProfile.ID
					c.portsProvisioned += 1

					// Set the new description
					if newPortName != "" {
						overrides[i].Name = newPortName
					}
					u.SetPortoverrides(site, usw.DeviceID, overrides)
				}
				return nil
			}
		}
	}
	return nil
}

func portBlocked(u *unifi.Unifi, site *unifi.Site, event unifi.EVT_SW_PoeDisconnect, blockProfile *unifi.PortProfile, c *counters) (blocked bool, err error) {

	// Get the switch
	usw, err := u.USW(site, event.SwName)
	if err != nil {
		return false, err
	}

	// Get the port
	overrides := usw.PortOverrides

	// Get the port
	for i := range usw.PortOverrides {
		if overrides[i].PortIdx == event.Port {
			// Port already blocked.
			if overrides[i].PortconfID == blockProfile.ID {
				c.portsBlocked += 1
				return true, nil
			}
		}
	}
	return false, nil
}

func matchProfile(u *unifi.Unifi, site *unifi.Site, event unifi.EVT_SW_PoeDisconnect, currProfile *unifi.PortProfile, c *counters) (match bool, err error) {

	// Get the switch
	usw, err := u.USW(site, event.SwName)
	if err != nil {
		return false, err
	}

	// Get the port
	overrides := usw.PortOverrides

	// Get the port
	for i := range usw.PortOverrides {
		if overrides[i].PortIdx == event.Port {
			// Match
			if overrides[i].PortconfID == currProfile.ID {
				c.events += 1
				return true, nil
			}
		}
	}
	return false, nil
}
