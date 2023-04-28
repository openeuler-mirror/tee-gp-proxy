tcpdump -vvvv -XX -i lo '(port 50051)' -w 01.cap
tcpdump -vvv -XX -r 01.cap  | more
