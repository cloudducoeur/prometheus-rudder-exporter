# Rudder Prometheus Exporter

A simple Prometheus exporter for the Rudder API.

## Building and Running

### Building

To build the exporter, you need to have Go installed.

```bash
go build -o prometheus-rudder-exporter .
```

### Running

You can run the exporter with the following command:

```bash
./prometheus-rudder-exporter --rudder.url=<RUDDER_URL> --rudder.api-token=<YOUR_API_TOKEN>
```

## Flags

- `--rudder.url`: The URL of the Rudder API (e.g., `https://rudder.example.com/rudder/api/latest`). (Required)
- `--rudder.api-token`: Your Rudder API token. (Required)
- `--web.listen-address`: The address to listen on for HTTP requests. (Default: `:9091`)

## Metrics Exposed

The exporter exposes the following metrics on the `/metrics` endpoint:

| Metric Name                | Description                   | Labels                 |
| -------------------------- | ----------------------------- | ---------------------- |
| `rudder_up`                | Whether the Rudder API is up. |                        |
| `rudder_global_compliance` | Global compliance percentage. |                        |
| `rudder_nodes_total`       | Total number of nodes.        |                        |
| `rudder_pending_nodes_total` | Total number of pending nodes. |                        |
| `rudder_groups_total` | Total number of groups. |                        |
| `rudder_rules_total`       | Total number of rules.        |                        |
| `rudder_directives_total`  | Total number of directives.   |                        |
| `rudder_node_compliance`   | Compliance per node.          | `node_id`, `node_hostname` |

### Example Output

```
# HELP rudder_up Wether the Rudder API is up.
# TYPE rudder_up gauge
rudder_up 1
# HELP rudder_global_compliance Global compliance percentage.
# TYPE rudder_global_compliance gauge
rudder_global_compliance 70
# HELP rudder_nodes_total Total number of nodes.
# TYPE rudder_nodes_total gauge
rudder_nodes_total 9
# HELP rudder_rules_total Total number of rules.
# TYPE rudder_rules_total gauge
rudder_rules_total 11
# HELP rudder_directives_total Total number of directives.
# TYPE rudder_directives_total gauge
rudder_directives_total 30
# HELP rudder_node_compliance Compliance per node.
# TYPE rudder_node_compliance gauge
rudder_node_compliance{node_hostname="dev-app-internal",node_id="d40076ff-6a7d-4887-b1a9-6c99c4b25e29"} 73.18
rudder_node_compliance{node_hostname="dev-db-01",node_id="ac42e42c-584b-42c0-adc5-621303f074e2"} 71.79
rudder_node_compliance{node_hostname="grafana",node_id="38a5d684-5fe1-4206-9b3c-809b2c54de1b"} 71.88
rudder_node_compliance{node_hostname="monitoring",node_id="736320a2-998b-45f2-9bad-864b01d48d88"} 55.41
rudder_node_compliance{node_hostname="prod-app-internal",node_id="10dd344c-3afd-4819-80de-9f34a5a6f205"} 74.8
rudder_node_compliance{node_hostname="prod-db-01",node_id="7c6c8cc8-d30b-41a9-a4f6-3a505ceb7b7c"} 72.59
rudder_node_compliance{node_hostname="rudder",node_id="root"} 45.75
rudder_node_compliance{node_hostname="windows-2019.priv.normation.com",node_id="030cff71-1c1e-4aea-beaf-e14f209396aa"} 100
rudder_node_compliance{node_hostname="windows-2022.priv.normation.com",node_id="15513437-7e63-4bf4-a212-397196ea8020"} 93.34
```
