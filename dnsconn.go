// Package dnsconn-server implements the server side of a stream connection
// using DNS as the underlying transport.
package dnsconn-server

/*
 * dnsconn.go
 * Stream over DNS
 * By J. Stuart McMurray
 * Created 20180822
 * Last Modified 20180825
 */

// NetworkName is the name returned by Addr's String method.
const NetworkName = "dnsconn"

type Addr struct{}

// Network returns NetworkName
func (a Addr) Network() string { return "dnsconn" }
func (a Addr) String() string  { /* TODO: Finish this */ return "" }
