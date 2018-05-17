// +build !linux

package netlink

type LinkUpdate struct {
}

func LinkSubscribe(ch chan<- LinkUpdate, done <-chan struct{}) error {
    return ErrNotImplemented
}
