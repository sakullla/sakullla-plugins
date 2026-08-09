# IP policy corpus

`cases.txt` is UTF-8/LF and deliberately contains documentation-only addresses
from RFC 5737 and RFC 3849. Each row is:

`id|address|provenance|expected_action|expected_reason`

The cases lock authenticated socket/PROXY/Relay handling, forged forwarded
metadata rejection, IPv4/IPv6 CIDR behavior, overlay isolation, and visible
MMDB expiry. No GeoLite database or production address is stored here.
