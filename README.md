# wintun-mitm

`wintun-mitm` is a Windows utility for performing man-in-the-middle attacks by routing all traffic through a [Wintun](https://wintun.net) adapter.

Currently supports passing through TCP and UDP traffic. 

## Prerequisites

* Windows
* [npcap](https://nmap.org/npcap/) or [winpcap](https://www.winpcap.org/)
* [wintun](https://wintun.net)
    * The `wintun.dll` should be placed next to the `wintun-mitm` binary

## Things to do

* Add an interface for modifying packets passing through the tunnel
* Add the ability to automatically set up routes
