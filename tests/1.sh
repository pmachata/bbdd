#!/bin/bash

setup_ns NS1 NS2
defer cleanup_all_ns

ip link add name L netns "$NS1" type veth peer name L netns "$NS2"
defer ip -n "$NS1" link del dev L

adf_ip_link_set_up "$NS1" L
adf_ip_link_set_up "$NS2" L

adf_ip_addr_add "$NS1" L 192.0.2.1/28
adf_ip_addr_add "$NS2" L 192.0.2.2/28

bbdd_start

ip -n "${NS1}" -br addr show dev L
ip -n "${NS2}" -br addr show dev L
