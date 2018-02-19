package netlink

import (
    "fmt"
    // "syscall"
    "errors"
    "net"
    "github.com/ndupreez/netlink/nl"
    "golang.org/x/sys/unix"
)


// --------------------------------------------------------------------------------
// Additional Netlink Generic functions to support L2TP tunnel
// operations
// Feb 2018
// Nick du Preez
// --------------------------------------------------------------------------------
const (
    L2TP_GENL_NAME = "l2tp"
    L2TP_ENCAPTYPE_UDP = 0
    L2TP_PWTYPE_ETH = 0x0005
    L2TP_PROTO_VERSION = 3
    L2TP_DEFAULT_MTU = 1460
)

const (
    L2TP_CMD_TUNNEL_CREATE  = 1
    L2TP_CMD_TUNNEL_DELETE  = 2
    L2TP_CMD_TUNNEL_MODIFY  = 3
    L2TP_CMD_TUNNEL_GET     = 4
    L2TP_CMD_SESSION_CREATE = 5
    L2TP_CMD_SESSION_DELETE = 6
    L2TP_CMD_SESSION_MODIFY = 7
    L2TP_CMD_SESSION_GET    = 8
)

const (
    L2TP_ATTR_NONE              = 0
    L2TP_ATTR_PW_TYPE           = 1
    L2TP_ATTR_ENCAP_TYPE        = 2
    L2TP_ATTR_PROTO_VERSION     = 7
    L2TP_ATTR_IFNAME            = 8
    L2TP_ATTR_CONN_ID           = 9
    L2TP_ATTR_PEER_CONN_ID      = 10
    L2TP_ATTR_SESSION_ID        = 11
    L2TP_ATTR_PEER_SESSION_ID   = 12
    L2TP_ATTR_COOKIE            = 15    /* 0, 4 or 8 bytes */
    L2TP_ATTR_PEER_COOKIE       = 16    /* 0, 4 or 8 bytes */
    L2TP_ATTR_DEBUG             = 17
    L2TP_ATTR_FD                = 23
    L2TP_ATTR_IP_SADDR          = 24    /* u32 */
    L2TP_ATTR_IP_DADDR          = 25    /* u32 */
    L2TP_ATTR_UDP_SPORT         = 26    /* u16 */
    L2TP_ATTR_UDP_DPORT         = 27    /* u16 */
    L2TP_ATTR_MTU               = 28
    L2TP_ATTR_STATS             = 30    /* nested */
)

const (
    L2TP_ATTR_STATS_NONE        = 0     /* no data */
    L2TP_ATTR_TX_PACKETS        = 1     /* u64 */
    L2TP_ATTR_TX_BYTES          = 2     /* u64 */
    L2TP_ATTR_TX_ERRORS         = 3     /* u64 */
    L2TP_ATTR_RX_PACKETS        = 4     /* u64 */
    L2TP_ATTR_RX_BYTES          = 5     /* u64 */
    L2TP_ATTR_RX_SEQ_DISCARDS   = 6     /* u64 */
    L2TP_ATTR_RX_OOS_PACKETS    = 7     /* u64 */
    L2TP_ATTR_RX_ERRORS         = 8     /* u64 */
    L2TP_ATTR_STATS_PAD         = 9
)

const (
    L2TP_SEQ_NONE   = 0
    L2TP_SEQ_IP     = 1
    L2TP_SEQ_ALL    = 2
)


// Used to cache some details regarding the L2TP environment
type L2tpContext struct {
    IsSet       bool
    ProtoID     uint16          // L2TP driver Genenric NL id
    Version     uint8           // L2TP driver version
}

// Structure to hold all session details
type L2tpSession struct {
    UniqueIDs   bool
    ID          uint32          // Local session ID
    PeerID      uint32          // Peer session ID
    IFName      string          // Session interface name
    MTU         uint16          // Interface MTU
}

// Structure to hold all tunnel details
type L2tpTunnel struct {
    ID          uint32          // Local tunnel ID
    PeerID      uint32          // Peer tunnel ID
    Name        string          // Tunnel endpoint name
    Cookie      string          // Tunnel cookie
    LocalAddr   string          // Local IP address in format 'ipaddr:port'
    PeerAddr    string          // Peer IP address in format 'ipaddr:port'
    Fd          uint32          // [Optional] Local UDP socket file descriptor to use
    Conn        *net.UDPConn    // Socket
    // Attached sessions
    Session     *L2tpSession    // For now - support 1 session per tunnel
    // Context
    ctx         L2tpContext
}

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


//
// 2. Context helpers
//
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

// Build a tunnel
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
    req.AddData(nl.NewRtAttr(L2TP_ATTR_FD, nl.Uint32Attr(tunnel.Fd)))

    _, err = req.Execute(unix.NETLINK_GENERIC, 0)

    return 0, err
}

func L2tpAddTunnel(tunnel *L2tpTunnel) (uint32, error) {
    return pkgHandle.L2tpAddTunnel(tunnel)
}

// Remove a tunnel
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

    // Remove the socket
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


// Add a session to a tunnel
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
        session.IFName = fmt.Sprintf("l2tpeth%d", session.ID)
    }
    if (session.MTU == 0) {
        session.MTU = L2TP_DEFAULT_MTU
    }
    // Fire request
    req := h.newNetlinkRequest(int(tunnel.ctx.ProtoID), unix.NLM_F_ACK)
    req.AddData(msg)
    req.AddData(nl.NewRtAttr(L2TP_ATTR_CONN_ID, nl.Uint32Attr(tunnel.ID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_PW_TYPE, nl.Uint16Attr(L2TP_PWTYPE_ETH)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_SESSION_ID, nl.Uint32Attr(session.ID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_PEER_SESSION_ID, nl.Uint32Attr(session.PeerID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_IFNAME, nl.ZeroTerminated(session.IFName)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_MTU, nl.Uint16Attr(session.MTU)))

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

// Remove a session
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

// Modify a session MTU
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

