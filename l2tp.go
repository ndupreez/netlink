package netlink

import (
    "net"
)


// --------------------------------------------------------------------------------
// Additional Netlink Generic functions to support L2TP tunnel
// operations
// Feb 2018
// Nick du Preez
// --------------------------------------------------------------------------------
const (
    L2TP_GENL_NAME      = "l2tp"
    L2TP_ENCAPTYPE_UDP  = 0
    L2TP_PWTYPE_ETH     = 0x0005
    L2TP_PROTO_VERSION  = 3
    L2TP_DEFAULT_MTU    = 1460
)

const (
    L2TP_CMD_TUNNEL_CREATE      = 1
    L2TP_CMD_TUNNEL_DELETE      = 2
    L2TP_CMD_TUNNEL_MODIFY      = 3
    L2TP_CMD_TUNNEL_GET         = 4
    L2TP_CMD_SESSION_CREATE     = 5
    L2TP_CMD_SESSION_DELETE     = 6
    L2TP_CMD_SESSION_MODIFY     = 7
    L2TP_CMD_SESSION_GET        = 8
)

const (
    L2TP_ATTR_NONE              = 0
    L2TP_ATTR_PW_TYPE           = 1
    L2TP_ATTR_ENCAP_TYPE        = 2
    L2TP_ATTR_L2SPEC_TYPE       = 5
    L2TP_ATTR_L2SPEC_LEN        = 6
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
    L2TP_ATTR_IP6_SADDR         = 31    /* struct in6_addr */
    L2TP_ATTR_IP6_DADDR         = 32    /* struct in6_addr */
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
    L2TP_SEQ_NONE               = 0
    L2TP_SEQ_IP                 = 1
    L2TP_SEQ_ALL                = 2
)

const (
    L2TP_L2SPECTYPE_NONE        = 0     /* len = 0 */
    L2TP_L2SPECTYPE_DEFAULT     = 1     /* len = 4 */
)

// See L2tpTunnel & L2tpSession debugflags
const (
    L2TP_MSG_DEBUG              = (1 << 0)
    L2TP_MSG_CONTROL            = (1 << 1)
    L2TP_MSG_SEQ                = (1 << 2)
    L2TP_MSG_DATA               = (1 << 3)
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
    Cookie      []byte          // HEX String - Tunnel cookie (max 8 bytes)
    PeerCookie  []byte          // HEX String - Tunnel cookie for peer (max 8 bytes)
    IFName      string          // Session interface name
    MTU         uint16          // Interface MTU
    L2SpecType  uint8           // L2TP_ATTR_L2SPEC_TYPE
    L2SpecLen   uint8           // L2TP_ATTR_L2SPEC_LEN
    DebugFlags  uint32          // Driver debug settings (bitmask)
}

// Structure to hold all tunnel details
type L2tpTunnel struct {
    ID          uint32          // Local tunnel ID
    PeerID      uint32          // Peer tunnel ID
    Name        string          // Tunnel endpoint name
    LocalAddr   string          // Local IP address in format 'ipaddr:port'
    PeerAddr    string          // Peer IP address in format 'ipaddr:port'
    Fd          uint32          // [Optional] Local UDP socket file descriptor to use
    Conn        *net.UDPConn    // Socket
    DebugFlags  uint32          // Driver debug settings (bitmask)
    // Attached sessions
    Session     *L2tpSession    // For now - support 1 session per tunnel
    // Context
    ctx         L2tpContext
}
