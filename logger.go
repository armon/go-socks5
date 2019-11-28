package socks5

type Logger interface {
	Printf(format string, v ...interface{})
}
