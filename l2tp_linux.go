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


//
// 2. Tunnel related APIs
//

// Build a tunnel
func (h *Handle) L2tpAddTunnel(tunnel *L2tpTunnel) (uint32, error) {
    // HACK HACK
    _, L2tpGlNetlinkID, err := pkgHandle.L2tpGetGenlDetails()
    if (err != nil) {
        return 1000, err
    }
    msg := &nl.Genlmsg{
        Command: L2TP_CMD_TUNNEL_CREATE,
        Version: 1,
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
    fmt.Printf("Conn is : %s (fd: %d) \n", tunnel.Conn, tunnel.Fd)
    req := h.newNetlinkRequest(int(L2tpGlNetlinkID), 0)
    req.AddData(msg)
    req.AddData(nl.NewRtAttr(L2TP_ATTR_CONN_ID, nl.Uint32Attr(tunnel.ID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_PEER_CONN_ID, nl.Uint32Attr(tunnel.PeerID)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_PROTO_VERSION, nl.Uint8Attr(L2TP_PROTO_VERSION)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_ENCAP_TYPE, nl.Uint16Attr(L2TP_ENCAPTYPE_UDP)))
    req.AddData(nl.NewRtAttr(L2TP_ATTR_FD, nl.Uint32Attr(tunnel.Fd)))

    // req.AddData(nl.NewRtAttr(L2TP_ATTR_IP_SADDR, []byte(localAddr.To4())))
    // req.AddData(nl.NewRtAttr(L2TP_ATTR_IP_DADDR, []byte(remoteAddr.To4())))
    // req.AddData(nl.NewRtAttr(L2TP_ATTR_UDP_SPORT, nl.Uint16Attr(5555)))
    // req.AddData(nl.NewRtAttr(L2TP_ATTR_UDP_DPORT, nl.Uint16Attr(6666)))

    _, err = req.Execute(unix.NETLINK_GENERIC, 0)
    fmt.Printf("Add tunnel err : %s\n", err)

    return 0, err
}

func L2tpAddTunnel(tunnel *L2tpTunnel) (uint32, error) {
    return pkgHandle.L2tpAddTunnel(tunnel)
}
