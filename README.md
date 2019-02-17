# check_unifi_poe_disconnect
Monitoring-Plugin (Icinga, Nagios, etc.) to secure POE port access in Ubiquiti UniFi networks.
(A feature which may be implemented by Ubiquiti itself in the future, but is missing at the moment)

Users without monitoring system can run it manually from the commandline or by a cron job.

## How it works
The plugin connects to a given UniFi controller and fetches the alerts of it.
Then it returns the number of active (non archived) POE disconnect events of ports with a given port-profile.

If configured, it provisiones the affected ports with a new (blocking) profile.

If provisioning is configured and archived alerts are detected,
the plugin reprovisions the port to the originating (unblocking) profile.

## Prerequisites
### 1. Alert Notification
By default, POE disconnect events are notified as events only. Since events can not be archived,
they must be notified as alerts (Settings / Notifications / Switch Events / PoE port disconnected)

### 2. Profiles
For simplicity and stability reasons the plugin does not support default profiles (ALL, disabled).
If not done already, at least the current network needs to be created (Settings / Profiles / Switch port )
#### Example:
- Name: AP
- PoE: PoE/PoE+
- Native-Network: LAN
- Tagged-Networks: None

If blocking is used, a second profile is needed as well.
#### Example:
- Name: AP-shutdown
- PoE: off
- Native-Network: None
- Tagged-Networks: None


Feedback, testing, using and contribution welcome.
