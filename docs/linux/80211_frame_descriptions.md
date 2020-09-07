# 802.11 frame descriptions
This document describes the current state of 802.11 frame descriptions.

This is not an exhaustive list as it does not include all frames/commands that are defined by 802.11 standards. However, it includes all frames supported by mac80211.

"Supported by mac80211" denotes whether the corresponding frame can be parsed and executed by mac80211 (802.11 SoftMAC implementation in Linux kernel).

## Frame types
### Data frames
Fully implemented.
* Supports QoS
* Supports HT field for QoS frames with order=1
* Does not generate encrypted frames

### Management frames
| Command | State | Supported by mac80211 |
| ------- | ----- | --------------------- |
| Association Request | implemented | yes |
| Association Response | implemented | yes |
| Reassociation Request | implemented | yes |
| Reassociation Response | implemented | yes |
| Probe Request | implemented | yes |
| Probe Response | implemented | yes |
| Timing Advertisement | not implemented | no |
| Beacon | implemented | yes |
| ATIM | not implemented | no |
| Disassociation | implemented | yes |
| Authentication |  implemented | yes |
| Deauthentication | implemented | yes |
| Action | see below | yes |
| Action No Ack | see below | no? |

#### Actions
| Category | Command | State | Supported by mac80211 |
| -------- | ------- | ----- | --------------------- |
| Spectrum Management | Measurement Request | partial implementation | receives and refuses |
| Spectrum Management | Measurement Report | not implemented | no |
| Spectrum Management | TPC Request | not implemented | no |
| Spectrum Management | TPC Report | not implemented | no |
| Spectrum Management | Channel Switch Announcement | implemented | yes |
| Block ACK | ADDBA Request | implemented | yes |
| Block ACK | ADDBA Response | implemented | yes |
| Block ACK | DELBA | implemented | yes |
| Public | Extended Channel Switch Announcement | implemented | yes |
| HT | Notify Channel Width |  implemented | yes |
| HT | SM Power Save |  implemented | yes |
| HT | PMSP | not implemented | no |
| HT | Set PCO Phase | not implemented | no |
| HT | CSI | not implemented | no |
| SA Query | SA Query Request |  implemented | yes |
| SA Query | SA Query Response | not implemented | no |
| TLDS | Setup Request | implemented | yes |
| TLDS | Setup Response | implemented | yes |
| TLDS | Setup Confirm | implemented | yes |
| TLDS | Teardown | implemented | yes |
| TLDS | Discover Request |  implemented | yes |
| TLDS | Channel Switch Request | implemented | yes |
| TLDS | Channel Switch Response | implemented | yes |
| Mesh | ? | not implemented | ? |
| Self Protected | Mesh Peering Open | not implemented | yes |
| Self Protected | Mesh Peering Close | not implemented | yes |
| Self Protected | Mesh Peering Confirm | not implemented | yes |
| VHT | Operating Mode Notification | not implemented | yes |
| VHT | Group ID Management | not implemented | yes |

### Control frames
| Command | State | Supported by mac80211 |
| ------- | ----- | --------------------- |
| Trigger | not implemented | no |
| Beamforming Report Poll | not implemented | no |
| VHT/HE NDP Announcement | not implemented | no |
| Control Frame Extension | not implemented | no |
| Control Wrapper | not implemented | no |
| Block Ack Request (BAR) | implemented (802.11n) | yes |
| Block Ack (BA) | implemented (802.11n) | ? |
| PS-Poll | implemented | ? |
| RTS | implemented | no |
| CTS | implemented | no |
| ACK | implemented | no |
| CF-End | implemented | ? |
| CF-End + CF-ACK | implemented | ? |

## Information Elements

| ID | IE | State | Supported by mac80211 |
| -- | -- | ----- | --------------------- |
| 0 | SSID | implemented | yes |
| 1 | Supported Rates | implemented | yes |
| 3 | DS | implemented | yes |
| 4 | CF | implemented | yes |
| 5 | Traffic Indication Map | implemented | yes |
| 6 | IBSS | implemented | yes |
| 7 | HT Capabilities | implemented | ? |
| 10 | Request | not implemented | no |
| 37 | Channel Switch Announcement | implemented | yes |
| 38 | Measurement Request | implemented | yes |
| 42 | Extended Rate PHY (ERP) | implemented | yes? |
| 55 | Fast BSS Transition element | implemented | yes |
| 60 | Extended Channel Switch Announcement | implemented | ? |
| 62 | Secondary Channel Offset | implemented | yes |
| 101 | Link Identifier | implemented | ? |
| 104 | Channel Switch Timing Information | implemented | ? |
| 118 | MESH Channel Switch | implemented | yes |
| 189 | GCR Group Address | implemented | no |

# Security
Not implemented