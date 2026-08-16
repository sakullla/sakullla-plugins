module github.com/sakullla/sakullla-plugins

go 1.26.5

require (
	github.com/klauspost/compress v1.19.2
	github.com/sakullla/nginx-reverse-emby/plugin-sdk v0.6.0
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	golang.org/x/mod v0.40.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240604185151-ef581f913117 // indirect
)

require (
	github.com/tetratelabs/wazero v1.12.0
	golang.org/x/sys v0.44.0
	google.golang.org/grpc v1.66.2
	google.golang.org/protobuf v1.34.2
)

// Temporary: consume the authorized host worktree until plugin-sdk publishes
// container.compose, http.rule, and ui.dynamic.
replace github.com/sakullla/nginx-reverse-emby/plugin-sdk => ../nginx-reverse-emby-zh-display/plugin-sdk
