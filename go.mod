module github.com/sakullla/sakullla-plugins

go 1.26.5

require github.com/sakullla/nginx-reverse-emby/plugin-sdk v0.0.0

require (
	github.com/tetratelabs/wazero v1.12.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	google.golang.org/protobuf v1.34.2
)

// Development-only linkage to the canonical SDK. Release candidates must
// replace this with the committed SDK pseudo-version before clean builds.
replace github.com/sakullla/nginx-reverse-emby/plugin-sdk => ../nginx-reverse-emby/plugin-sdk
