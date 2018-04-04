// +build !linux

package netlink

func (h *Handle) L2tpGetGenlVersion() (uint32, error) {
    return 0, ErrNotImplemented
}

func L2tpGetGenlVersion() (uint32, error) {
    return 0, ErrNotImplemented
}

func L2tpIsAvailable() (bool, error) {
    return false, ErrNotImplemented
}

func L2tpAddTunnelForConn(tunnel *L2tpTunnel) (uint32, error) {
    return 0, ErrNotImplemented
}

func L2tpAddTunnel(tunnel *L2tpTunnel) (uint32, error) {
    return 0, ErrNotImplemented
}

func L2tpDelTunnel(tunnel *L2tpTunnel) (uint32, error) {
    return 0, ErrNotImplemented
}

func L2tpAddSession(tunnel *L2tpTunnel, session *L2tpSession) (uint32, error) {
    return 0, ErrNotImplemented
}

func L2tpDelSession(tunnel *L2tpTunnel) (uint32, error) {
    return 0, ErrNotImplemented
}

func L2tpSetSessionMtu(tunnel *L2tpTunnel, mtu uint16) (uint32, error) {
    return 0, ErrNotImplemented
}
