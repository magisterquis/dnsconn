package resolver

/*
 * query.go
 * perform a query
 * By J. Stuart McMurray
 * Created 20180926
 * Last Modified 20180926
 */

import "golang.org/x/net/dns/dnsmessage"

/* query makes a query for the name and given type and returns all of the
answers it gets. */
func (r *resolver) query(
	name string,
	qtype dnsmessage.Type,
) ([]dnsmessage.Resource, error) {
	var (
		ans []byte
		err error
	)

	/* If we have an already-"connected" packetconn, use that */
	if nil != r.pc {
		ans, err = r.queryPC(name, qtype)
	} else {
		ans, err = r.queryServers(name, qtype)
	}
	if nil != err {
		return nil, err
	}

	/* TODO: Finish this */

}

/* queryPC makes a query via the "connected" packetconn */
func (r *resolver) queryPC(name string, qtype dnsmessage.Type) ([]byte, error) {
	/* TODO: Finish this */
}

/* queryServers makes a query via the configured server(s) */
func (r *resolver) queryServers(name string, qtype dnsmessage.Type) ([]byte, error) {
	/* TODO: Finish this */
}
