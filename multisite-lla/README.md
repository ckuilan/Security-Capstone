# Multisite EVPN Fabric with IPv6 LLA and DCI

A production-grade, enterprise-scale data center fabric topology featuring:

## Architecture Overview

### Site 1 (Primary)
- **Super-Spines**: ss3 (64660), ss4 (64660)
- **Spines**: spine3 (64661), spine4 (64661)
- **Leafs**: leaf4, leaf5, leaf6 (all 64662)

### Site 2 (Secondary)
- **Super-Spines**: ss5 (64665), ss6 (64665)
- **Spines**: spine5 (64661), spine6 (64661)
- **Leafs**: leaf7, leaf8, leaf9 (all 64662)

### Core
- **Core Router**: 192.168.0.100 (AS 65000) - DCI hub connecting both sites

## Key Features

### Underlay Network
- **IPv6 Link-Local (LLA)** underlay - no IPv4 on data plane interfaces
- eBGP interface-based peering (Et1-3)
- Link-local addresses are auto-assigned and collision-free
- Clean separation of concerns: management (172.20.30.0/24) vs. data plane

### Overlay Network
- **EVPN RFC 7432** multihop peering on loopback addresses
- VRF-based multi-tenancy (tenant-a, tenant-b, tenant-c)
- VXLAN encapsulation (VNI 100, 200, 300)
- DCI extension through core-router for inter-site connectivity

### Tenant Configuration

| Tenant | VLAN (Site 1) | VLAN (Site 2) | VNI | Subnet Site 1 | Subnet Site 2 | RT |
|--------|---------------|---------------|-----|---------------|---------------|----|
| tenant-a | 100 | 1100 | 100 | 10.10.0.0/24 | 10.20.0.0/24 | 64660:100 / 64665:100 |
| tenant-b | 200 | 1200 | 200 | 10.10.1.0/24 | 10.20.1.0/24 | 64660:200 / 64665:200 |
| tenant-c | 300 | 1300 | 300 | 10.10.2.0/24 | 10.20.2.0/24 | 64660:300 / 64665:300 |

## Loopback Addressing

**Site 1:**
- ss3: 192.168.0.1
- ss4: 192.168.0.3
- spine3: 192.168.0.2
- spine4: 192.168.0.4
- leaf4: 192.168.1.1
- leaf5: 192.168.1.2
- leaf6: 192.168.1.3

**Site 2:**
- ss5: 192.168.0.5
- ss6: 192.168.0.6
- spine5: 192.168.0.7
- spine6: 192.168.0.8
- leaf7: 192.168.2.1
- leaf8: 192.168.2.2
- leaf9: 192.168.2.3

**Core:**
- core-router: 192.168.0.100

## Management Network

All nodes have management interfaces on 172.20.30.0/24:
- core-router: 172.20.30.100
- ss3: 172.20.30.10
- ss4: 172.20.30.3
- ss5: 172.20.30.105
- ss6: 172.20.30.106
- spine3: 172.20.30.9
- spine4: 172.20.30.6
- spine5: 172.20.30.107
- spine6: 172.20.30.108
- leaf4-6: 172.20.30.8-4
- leaf7-9: 172.20.30.117-119

## BGP Peering Strategy

### Underlay (Interface-based IPv6 LLA)
- Super-Spines peer with Spines (Et1-2)
- Spines peer with Leafs (Et3-5)

### Overlay (Multihop EVPN)
- All Leafs ↔ Super-Spines within site
- All Super-Spines ↔ Core-Router (DCI)
- `allowas-in 2` on leafs for same-AS EVPN consolidation

## Deployment

```bash
clab deploy -t link-local-topology.clab.yml
```

## Verification

Key commands to verify functionality:
```
# BGP underlay
show bgp ipv4 summary
show ipv6 bgp summary

# EVPN overlay
show bgp evpn summary
show bgp evpn route-type ip-prefix detail

# VXLAN
show vxlan vtep
show vxlan vni detail

# Tenant routes
show ip route vrf tenant-a
show vrf all
```

## Design Rationale

This topology demonstrates:
- **Scalability**: Leaf-spine-super-spine model scales to 1000+ leafs
- **Redundancy**: Dual paths through multiple super-spines and spines
- **Modern Underlay**: IPv6 LLA eliminates manual IPv4 configuration on data path
- **Clean DCI**: EVPN over overlay allows per-tenant connectivity across sites
- **Enterprise Standards**: Multi-tenancy, traffic isolation, proper addressing schemes

## Notes

- This is a containerlab simulation using Arista cEOS 4.35.1F
- IPv6 LLA is automatically configured and collision-free
- Management plane is logically separated for security
- All loopbacks are unique globally
- All tenant subnets are unique per site to simulate multi-site deployment
