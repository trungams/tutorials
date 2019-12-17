# Implementation of Selective Port Mirroring in P4

### Running the version with selective port mirroring during ingress

```bash
$ cp ingress/* .
```

### Running the version with selective port mirroring during egress

```bash
$ cp egress/* .
```

### To run the experiments

The first step is to start the network topology. Run the following command inside a terminal

```bash
$ make
```

To enable port mirroring, open another terminal and run

```bash
simple_switch_CLI --thrift-port 9090
> mirroring_add 5 3      # if running ingress processing version
> mirroring_add 11 3     # if running egress processing version
```

Inside Mininet CLI, run these commands to test connectivity and open new terminals for the virtual hosts

```bash
mininet> pingall
mininet> xterm h1 h2
```

Inside `h2`'s, run `./http_server.sh` to start the HTTP server on node `h2`. On `h1`, run `./http_client.sh` to start sending requests from `h1`. After the client has stopped, exit the Mininet CLI and then you can start analyzing the pcap files inside `pcaps/` directory.
