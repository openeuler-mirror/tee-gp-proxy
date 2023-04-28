# bin/spire-server entry create \
#  -parentID spiffe://example.org/myagent \
#  -spiffeID spiffe://example.org/myservice \
#  -selector unix:uid:$(id -u)

bin/spire-server entry create \
   -parentID spiffe://example.org/myagent \
   -spiffeID spiffe://example.org/myservice \
   -selector unix:uid:1000
