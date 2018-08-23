// +build !linux

package netlink

import (
    "github.com/vishvananda/netlink/nl"
    "golang.org/x/sys/unix"
)

type LinkUpdate struct {
    nl.IfInfomsg
    Header unix.NlMsghdr
    Link
}

func LinkSubscribe(ch chan<- LinkUpdate, done <-chan struct{}) error {
    return ErrNotImplemented
}
