// +build !linux

package netlink

type AddrUpdate struct {
}

func AddrSubscribe(ch chan<- AddrUpdate, done <-chan struct{}) error {
    return ErrNotImplemented
}
