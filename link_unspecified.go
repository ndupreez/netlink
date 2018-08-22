// +build !linux

package netlink

type LinkUpdate struct {
    nl.IfInfomsg
    Header unix.NlMsghdr
    Link
}

func LinkSubscribe(ch chan<- LinkUpdate, done <-chan struct{}) error {
    return ErrNotImplemented
}
