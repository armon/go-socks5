go-socks5 [![Build Status](https://travis-ci.org/armon/go-socks5.png)](https://travis-ci.org/armon/go-socks5)
=========

Provides the `socks5` package that implements a [SOCKS5 server](http://en.wikipedia.org/wiki/SOCKS).
SOCKS (Secure Sockets) is used to route traffic between a client and server through
an intermediate proxy layer. This can be used to bypass firewalls or NATs.

Feature
=======

The package has the following features:
* "No Auth" mode
* User/Password authentication
* Support for the CONNECT command
* Rules to do granular filtering of commands
* Custom DNS resolution
* Unit tests

TODO
====

The package still needs the following:
* Support for the BIND command
* Support for the ASSOCIATE command

