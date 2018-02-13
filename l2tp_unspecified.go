// +build !linux

package netlink

func (h *Handle) L2tpGetGenlVersion() (uint32, error) {
    return 0, ErrNotImplemented
}

func L2tpGetGenlVersion() (uint32, error) {
    return 0, ErrNotImplemented
}
