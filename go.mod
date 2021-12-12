module github.com/chrisfenner/crypto

go 1.17

require (
	golang.org/x/crypto v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1
	golang.org/x/term v0.0.0-20201126162022-7de9c90e9dd1
)

require golang.org/x/text v0.3.6 // indirect

replace golang.org/x/crypto => github.com/chrisfenner/crypto v0.0.0-20211212021344-34055e1e84a5
