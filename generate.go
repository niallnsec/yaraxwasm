package yaraxwasm

//go:generate easyjson -snake_case -pkg -output_filename structs_easyjson.go
//go:generate sh -c "cd guest && cargo build-web-release"
//go:generate sh -c "mkdir -p internal/module && zstd --ultra -22 --force --quiet -o internal/module/yarax_guest.wasm.zst guest/release/yarax_guest.wasm"
