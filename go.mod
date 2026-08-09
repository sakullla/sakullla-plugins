module github.com/sakullla/sakullla-plugins

go 1.26.5

require github.com/sakullla/nginx-reverse-emby/plugin-sdk/go v0.0.0

// Development-only linkage to the canonical SDK. Release candidates must
// replace this with the committed SDK pseudo-version before clean builds.
replace github.com/sakullla/nginx-reverse-emby/plugin-sdk/go => ../nginx-reverse-emby/plugin-sdk/go
