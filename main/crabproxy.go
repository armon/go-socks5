package main

import (
    ".."
    "flag"
)

func main() {
    flag.Parse()
    conf := &socks5.Config{}
    conf.Credentials = socks5.StaticCredentials{"foo": "foopass"}
    server, err := socks5.New(conf)
    if err != nil {
        panic(err)
    }

    if err := server.ListenAndServe("tcp", "0.0.0.0:9999"); err != nil {
        panic(err)
    }
}
