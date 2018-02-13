package netlink

import (
    // "fmt"
    // "syscall"

    // "github.com/ndupreez/netlink/nl"
    // "golang.org/x/sys/unix"
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

type L2tpTunnel struct {
    ID      uint16
    HdrSize uint32
    Name    string
    Version uint32
    MaxAttr uint32
    Ops     []GenlOp
    Groups  []GenlMulticastGroup
}

// Retrieve the GeNl driver version
func (h *Handle) L2tpGetGenlVersion() (uint32, error) {
    // Read genl driver details
    l2tp, err := GenlFamilyGet(L2TP_GENL_NAME)
    if (err != nil) {
        return 0, err
    }
    // Retrieve the versiom
    return l2tp.Version, nil
}

func L2tpGetGenlVersion() (uint32, error) {
    return pkgHandle.L2tpGetGenlVersion()
}

// Build a tunnel


