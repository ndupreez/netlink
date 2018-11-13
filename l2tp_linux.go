package netlink

import (
    "fmt"
    // "syscall"
    "errors"
    "net"
    "strconv"
    "strings"
    "github.com/ndupreez/netlink/nl"
    "golang.org/x/sys/unix"
)


// --------------------------------------------------------------------------------
// Additional Netlink Generic functions to support L2TP tunnel
// operations
// Feb 2018
// Nick du Preez
// --------------------------------------------------------------------------------

//
// 1. Utility functions:
//
// Retrieve the GeNl L2TP driver version supported
func (h *Handle) L2tpGetGenlVersion() (uint32, error) {
    // Read genl driver details
    l2tp, err := GenlFamilyGet(L2TP_GENL_NAME)
    if (err != nil) {
        return 0, err
    }
    // Retrieve the version
    return l2tp.Version, nil
}

func L2tpGetGenlVersion() (uint32, error) {
    return pkgHandle.L2tpGetGenlVersion()
}

// Retrieve the GeNl L2TP family ID
func (h *Handle) L2tpGetGenlFamilyId() (uint16, error) {
    // Read genl driver details
    l2tp, err := GenlFamilyGet(L2TP_GENL_NAME)
    if (err != nil) {
        return 0, err
    }
    // Retrieve the family/driver ID
    return l2tp.ID, nil
}

func L2tpGetGenlFamilyId() (uint16, error) {
    return pkgHandle.L2tpGetGenlFamilyId()
}

// Retrieve the GeNl L2TP family ID and version
func (h *Handle) L2tpGetGenlDetails() (uint32, uint16, error) {
    // Read genl driver details
    l2tp, err := GenlFamilyGet(L2TP_GENL_NAME)
    if (err != nil) {
        return 0, 0, err
    }
    // Retrieve the version and family/driver ID
    return l2tp.Version, l2tp.ID, nil
}

func L2tpGetGenlDetails() (uint32, uint16, error) {
    return pkgHandle.L2tpGetGenlDetails()
}

// Check to see if we can talk to the L2TP netlink driver
func L2tpIsAvailable() (bool, error) {
    L2tpGlNetlinkVer, _, err := pkgHandle.L2tpGetGenlDetails()
    if (err != nil) {
        return false, err
    }
    if (L2tpGlNetlinkVer < 1) {
        return false, errors.New("Unknown driver version")
    }
    return true, nil
}

// Extract port for address
func GetPortFromAddr(addr string) uint16 {
    var portInt uint16
    portInt = 0
    _, port, err := net.SplitHostPort(addr)
    if (err == nil) {
        tempPort, errConv := strconv.ParseUint(port, 10, 16)
        if (errConv == nil) {
            portInt = (uint16)(tempPort)
        }
    }
    return (portInt)
}

// Extract host part from address
func GetHostFromAddr(addr string) string {
    if (!strings.Contains(addr, ":")) {
        return (addr)
    }
    host, _, err := net.SplitHostPort(addr)
    if (err == nil) {
        return (host)
    }
    return ("")
}

func IsIPv6(str string) bool {
  ip := net.ParseIP(str)
  return ip != nil && strings.Contains(str, ":")
}


//
// 2. Context helpers
//

// The APIs use a 'created-on-demand' context struct to keep track of information
// accross invokes, mainly to reduce the overhead of subsequent calls to the driver,
// like driver GeNL ID, version, etc.
func setL2tpContext(tunnel *L2tpTunnel) (error) {
    if (tunnel.ctx.IsSet) {
        // Already loaded
        return nil
    }
    L2tpGlNetlinkVer, L2tpGlNetlinkID, err := pkgHandle.L2tpGetGenlDetails()
    if (err != nil) {
        return err
    }
    tunnel.ctx.Version = uint8(L2tpGlNetlinkVer)
    tunnel.ctx.ProtoID = L2tpGlNetlinkID
    tunnel.ctx.IsSet = true

    return nil
}


//
// 3. Tunnel & Session related APIs
//

//
// Build or add a tunnel using a user space UDP socket for the L2TP driver to
// convert into a L2TP version
//
func (h *Handle) L2tpAddTunnelForConn(tunnel *L2tpTunnel) (uint32, error) {
    //
    // NOTE:
    // Work in Progress!
    //

    // Check context
    err := setL2tpContext(tunnel)
    if (err != nil) {
        return 1000, err
    }
    msg := &nl.Genlmsg{
        Command: L2TP_CMD_TUNNEL_CREATE,
        Version: tunnel.ctx.Version,
    }
    var localAddr *net.UDPAddr
    var remoteAddr *net.UDPAddr
    var addrErr error
    // Resolve the 2 endpoint addresses
    if (len(tunnel.LocalAddr) != 0) {
        localAddr, addrErr = net.ResolveUDPAddr("udp", tunnel.LocalAddr)
        if (addrErr != nil) {
            return 1001, addrErr
        }
    }
    if (len(tunnel.PeerAddr) != 0) {
        remoteAddr, addrErr = net.ResolveUDPAddr("udp", tunnel.PeerAddr)
        if (addrErr != nil) {
            return 1002, addrErr
        }
    } else {
        return 1003, errors.New("Peer address not found")
    }
    // Open the socket
    var connErr error
    tunnel.Conn, connErr = net.DialUDP("udp", localAddr, remoteAddr)
    if (connErr != nil) {
        return 1004, connErr
    }
    connFile, _ := tunnel.Conn.File()
    tunnel.Fd = (uint32)(connFile.Fd())
    // Fire request
    req := h.newNetlinkRequest(int(tunnel.ctx.ProtoID), unix.NLM_F_ACK)
    req.AddData(msg)
    req.AddData(nl.NewRtAttr(L2TP_ATTR_CONN_ID, nl.Uint32Attr(tunnel.ID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_PEER_CONN_ID, nl.Uint32Attr(tunnel.PeerID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_PROTO_VERSION, nl.Uint8Attr(L2TP_PROTO_VERSION)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_ENCAP_TYPE, nl.Uint16Attr(L2TP_ENCAPTYPE_UDP)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_DEBUG, nl.Uint32Attr(tunnel.DebugFlags)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_FD, nl.Uint32Attr(tunnel.Fd)))

    _, err = req.Execute(unix.NETLINK_GENERIC, 0)

    return 0, err
}

func L2tpAddTunnelForConn(tunnel *L2tpTunnel) (uint32, error) {
    return pkgHandle.L2tpAddTunnelForConn(tunnel)
}


//
// Build or add a tunnel using the 2 endpoints (addresses & ports)
//
func (h *Handle) L2tpAddTunnel(tunnel *L2tpTunnel) (uint32, error) {
    // Check context
    err := setL2tpContext(tunnel)
    if (err != nil) {
        return 1000, err
    }
    msg := &nl.Genlmsg{
        Command: L2TP_CMD_TUNNEL_CREATE,
        Version: tunnel.ctx.Version,
    }
    var addrErr error
    // Resolve the 2 endpoint addresses
    if (len(tunnel.LocalAddr) != 0) {
        _, addrErr = net.ResolveUDPAddr("udp", tunnel.LocalAddr)
        if (addrErr != nil) {
            return 1001, addrErr
        }
    }
    if (len(tunnel.PeerAddr) != 0) {
        _, addrErr = net.ResolveUDPAddr("udp", tunnel.PeerAddr)
        if (addrErr != nil) {
            return 1002, addrErr
        }
    } else {
        return 1003, errors.New("Peer address not found")
    }
    // Fire request
    req := h.newNetlinkRequest(int(tunnel.ctx.ProtoID), unix.NLM_F_ACK)
    req.AddData(msg)
    req.AddData(nl.NewRtAttr(L2TP_ATTR_CONN_ID, nl.Uint32Attr(tunnel.ID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_PEER_CONN_ID, nl.Uint32Attr(tunnel.PeerID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_PROTO_VERSION, nl.Uint8Attr(L2TP_PROTO_VERSION)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_ENCAP_TYPE, nl.Uint16Attr(L2TP_ENCAPTYPE_UDP)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_DEBUG, nl.Uint32Attr(tunnel.DebugFlags)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_UDP_SPORT, nl.Uint16Attr(GetPortFromAddr(tunnel.LocalAddr))))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_UDP_DPORT, nl.Uint16Attr(GetPortFromAddr(tunnel.PeerAddr))))
    // IPv4 or v6?
    localHost := GetHostFromAddr(tunnel.LocalAddr)
    peerHost  := GetHostFromAddr(tunnel.PeerAddr)
    localIP := net.ParseIP(localHost)
    peerIP  := net.ParseIP(peerHost)
    if (IsIPv6(localHost)) {
        req.AddData(nl.NewRtAttr(L2TP_ATTR_IP6_SADDR, localIP.To16()))
        req.AddData(nl.NewRtAttr(L2TP_ATTR_IP6_DADDR, peerIP.To16()))
    } else {
        req.AddData(nl.NewRtAttr(L2TP_ATTR_IP_SADDR, localIP.To4()))
        req.AddData(nl.NewRtAttr(L2TP_ATTR_IP_DADDR, peerIP.To4()))
    }

    _, err = req.Execute(unix.NETLINK_GENERIC, 0)

    return 0, err
}

func L2tpAddTunnel(tunnel *L2tpTunnel) (uint32, error) {
    return pkgHandle.L2tpAddTunnel(tunnel)
}

//
// Remove a tunnel and in the process remove all associated sessions.
//
func (h *Handle) L2tpDelTunnel(tunnel *L2tpTunnel) (uint32, error) {
    // Check context
    err := setL2tpContext(tunnel)
    if (err != nil) {
        return 1000, err
    }
    msg := &nl.Genlmsg{
        Command: L2TP_CMD_TUNNEL_DELETE,
        Version: tunnel.ctx.Version,
    }
    // Is the session nil?
    if (tunnel.Session != nil) {
        L2tpDelSession(tunnel)
    }
    // Fire request
    req := h.newNetlinkRequest(int(tunnel.ctx.ProtoID), unix.NLM_F_ACK)
    req.AddData(msg)
    req.AddData(nl.NewRtAttr(L2TP_ATTR_CONN_ID, nl.Uint32Attr(tunnel.ID)))

    _, err = req.Execute(unix.NETLINK_GENERIC, 0)

    // Close socket - if open
    if (err == nil) {
        if (tunnel.Conn != nil) {
            tunnel.Conn.Close()
            tunnel.Conn = nil
        }
    }

    return 0, err
}

func L2tpDelTunnel(tunnel *L2tpTunnel) (uint32, error) {
    return pkgHandle.L2tpDelTunnel(tunnel)
}

//
// Add a session to a tunnel (current version supports 1 session per tunnel)
//
func (h *Handle) L2tpAddSession(tunnel *L2tpTunnel, session *L2tpSession) (uint32, error) {
    // Check context
    err := setL2tpContext(tunnel)
    if (err != nil) {
        return 1000, err
    }
    msg := &nl.Genlmsg{
        Command: L2TP_CMD_SESSION_CREATE,
        Version: tunnel.ctx.Version,
    }
    if (tunnel.Session != nil) {
        return 2000, errors.New("Tunnel already has session associated")
    }
    if (session.ID == 0) {
        if (session.UniqueIDs) {
            session.ID = tunnel.ID
        } else {
            session.ID = 1
        }
    }
    if (session.PeerID == 0) {
        if (session.UniqueIDs) {
            session.PeerID = tunnel.PeerID
        } else {
            session.PeerID = 1
        }
    }
    if (len(session.IFName) == 0) {
        session.IFName = fmt.Sprintf("l2tpeth%d", tunnel.ID)
    }
    // Fire request
    req := h.newNetlinkRequest(int(tunnel.ctx.ProtoID), unix.NLM_F_ACK)
    req.AddData(msg)
    req.AddData(nl.NewRtAttr(L2TP_ATTR_CONN_ID, nl.Uint32Attr(tunnel.ID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_PW_TYPE, nl.Uint16Attr(L2TP_PWTYPE_ETH)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_L2SPEC_TYPE, nl.Uint8Attr(session.L2SpecType)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_L2SPEC_LEN, nl.Uint8Attr(session.L2SpecLen)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_SESSION_ID, nl.Uint32Attr(session.ID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_PEER_SESSION_ID, nl.Uint32Attr(session.PeerID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_IFNAME, nl.ZeroTerminated(session.IFName)))
    if (session.MTU > 0) {
        req.AddData(nl.NewRtAttr(L2TP_ATTR_MTU, nl.Uint16Attr(session.MTU)))
    }
    if (len(session.Cookie) > 0) {
        req.AddData(nl.NewRtAttr(L2TP_ATTR_COOKIE, session.Cookie))
    }
    if (len(session.PeerCookie) > 0) {
        req.AddData(nl.NewRtAttr(L2TP_ATTR_PEER_COOKIE, session.PeerCookie))
    }
    req.AddData(nl.NewRtAttr(L2TP_ATTR_DEBUG, nl.Uint32Attr(session.DebugFlags)))

    _, err = req.Execute(unix.NETLINK_GENERIC, 0)

    // OK? Add it to our tunnel
    if (err == nil) {
        tunnel.Session = session
    }

    return 0, err
}

func L2tpAddSession(tunnel *L2tpTunnel, session *L2tpSession) (uint32, error) {
    return pkgHandle.L2tpAddSession(tunnel, session)
}

//
// Remove a session from a tunnel. Current version assumes 1 session per
// tunnel
//
func (h *Handle) L2tpDelSession(tunnel *L2tpTunnel) (uint32, error) {
    // Check context
    err := setL2tpContext(tunnel)
    if (err != nil) {
        return 1000, err
    }
    if (tunnel.Session == nil) {
        return 2001, errors.New("Tunnel has no attached sessions")
    }
    msg := &nl.Genlmsg{
        Command: L2TP_CMD_SESSION_DELETE,
        Version: tunnel.ctx.Version,
    }
    // Fire request
    req := h.newNetlinkRequest(int(tunnel.ctx.ProtoID), unix.NLM_F_ACK)
    req.AddData(msg)
    req.AddData(nl.NewRtAttr(L2TP_ATTR_CONN_ID, nl.Uint32Attr(tunnel.ID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_SESSION_ID, nl.Uint32Attr(tunnel.Session.ID)))

    _, err = req.Execute(unix.NETLINK_GENERIC, 0)

    // Remove the session from tunnel
    if (err == nil) {
        tunnel.Session = nil
    }

    return 0, err
}

func L2tpDelSession(tunnel *L2tpTunnel) (uint32, error) {
    return pkgHandle.L2tpDelSession(tunnel)
}

//
// Modify a session MTU
//
func (h *Handle) L2tpSetSessionMtu(tunnel *L2tpTunnel, mtu uint16) (uint32, error) {
    // Check context
    err := setL2tpContext(tunnel)
    if (err != nil) {
        return 1000, err
    }
    msg := &nl.Genlmsg{
        Command: L2TP_CMD_SESSION_MODIFY,
        Version: tunnel.ctx.Version,
    }
    if (tunnel.Session == nil) {
        return 2001, errors.New("No session associated with tunnel")
    }
    tunnel.Session.MTU = mtu
    // Fire request
    req := h.newNetlinkRequest(int(tunnel.ctx.ProtoID), unix.NLM_F_ACK)
    req.AddData(msg)
    req.AddData(nl.NewRtAttr(L2TP_ATTR_CONN_ID, nl.Uint32Attr(tunnel.ID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_SESSION_ID, nl.Uint32Attr(tunnel.Session.ID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_MTU, nl.Uint16Attr(tunnel.Session.MTU)))

    _, err = req.Execute(unix.NETLINK_GENERIC, 0)

    return 0, err
}

func L2tpSetSessionMtu(tunnel *L2tpTunnel, mtu uint16) (uint32, error) {
    return pkgHandle.L2tpSetSessionMtu(tunnel, mtu)
}

