# Intro
Gocrypt's functions are designed to simplify the use of Golang's
[default crypto package](https://golang.org/pkg/crypto). In particular,
the first version of this repo includes AES helper functions that work with
io.Readers and io.Writers, rather than []byte arrays directly. This has the
benefit of allowing files to be used directly, rather than having to either
load the entire file into RAM.

# Docs
As with all Go packages, documentation can be found on
[godoc.org](https://godoc.org/github.com/traherom/gocrypt).

# Install
     $ go get github.com/traherom/gocrypt
