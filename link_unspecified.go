// +build !linux

package netlink

type LinkUpdate struct {
    Link    struct{}
}

func LinkSubscribe(ch chan<- LinkUpdate, done <-chan struct{}) error {
    return ErrNotImplemented
}
