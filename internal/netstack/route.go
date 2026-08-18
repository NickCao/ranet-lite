package netstack

import (
	"fmt"
	"math/bits"
	"net/netip"
	"sync"
)

// Peer is one mesh neighbor: encryptFn encrypts a raw tunnel-mode IP packet
// (nextHeader is esp.NextHeaderIPv4/IPv6), and the transmit functions hand
// sealed results to the wire. They're kept separate, rather
// than one combined send step, so Mesh.outboundLoop can run the expensive
// part -- encryption -- across as many parallel workers as there are
// cores for any peer's traffic, while still calling transmitFn for one
// peer's packets in their original relative order (see outboundLoop's doc
// comment for why that matters and why this split, rather than pinning a
// peer or flow to one fixed worker, is what lets a single peer actually
// use every core). Decoupling delivery from the TUN plumbing this way
// also makes the stack wiring testable without a real TUN device or
// ESP/UDP (see mesh_test.go).
type Peer struct {
	ID              string
	encryptFn       func(raw []byte, nextHeader byte) ([]byte, error)
	transmitFn      func(sealed []byte) error
	transmitBatchFn func(sealed [][]byte) error
}

func NewPeer(id string, encryptFn func(raw []byte, nextHeader byte) ([]byte, error), transmitFn func(sealed []byte) error) *Peer {
	return &Peer{
		ID: id, encryptFn: encryptFn, transmitFn: transmitFn,
		transmitBatchFn: func(sealed [][]byte) error {
			for _, packet := range sealed {
				if err := transmitFn(packet); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// NewPeerBatched preserves completed TUN batches through the transport handoff.
func NewPeerBatched(id string, encryptFn func(raw []byte, nextHeader byte) ([]byte, error), transmitBatchFn func(sealed [][]byte) error) *Peer {
	return &Peer{
		ID: id, encryptFn: encryptFn, transmitBatchFn: transmitBatchFn,
		transmitFn: func(sealed []byte) error {
			return transmitBatchFn([][]byte{sealed})
		},
	}
}

// SendRaw transmits a hand-built tunnel-mode IP packet directly through
// this peer, bypassing the mesh's route table and its order-preserving
// pipeline. Used by protocols that address a specific peer directly
// rather than by destination IP — e.g. internal/babel, which multicasts
// through each peer's own ESP tunnel rather than routing by the
// (link-local, often peer-agnostic) destination address. Low volume, and
// already strictly sequential relative to itself, so no ordering concern.
func (p *Peer) SendRaw(raw []byte, nextHeader byte) error {
	sealed, err := p.encryptFn(raw, nextHeader)
	if err != nil {
		return err
	}
	return p.transmitFn(sealed)
}

// RouteTable maps (source, destination) prefix pairs to the peer that can
// reach them — including source-specific (SADR,
// draft-ietf-babel-source-specific) routes, which an embedded babel
// speaker installs directly rather than approximating: since this mesh's
// own TUN device sees every packet's real source and destination address
// directly, there's no need to guess whether a source-specific route
// "applies to us" the way a destination-only route table would have to.
//
// Lookup is a binary patricia trie over destination addresses (one for
// IPv4, one for IPv6), giving O(address bit-width) cost instead of the
// O(number of routes) a linear scan needs -- confirmed as a real,
// significant cost (12%+ of total CPU, in two separate profiles) once
// this mesh's outbound pipeline is otherwise well-parallelized and
// pushing enough packets/sec for it to matter. The trie mechanism itself
// is ported from wireguard-go's device.AllowedIPs (device/allowedips.go),
// which solves the identical "address -> peer by longest matching
// prefix" problem for WireGuard's own peer selection -- not reimplemented
// from scratch, and not WireGuard-proprietary logic either (it's a
// standard technique). That type isn't usable here directly: its
// Lookup/Insert are hard-typed to wireguard-go's own *device.Peer, a
// large struct tightly coupled to its Noise-protocol/handshake state,
// not substitutable for netstack.Peer, and it has no concept of
// source-specific matching at all. What's ported is the trie mechanism,
// simplified to use an explicit parent pointer instead of that version's
// unsafe.Pointer parent-offset trick (a memory-layout micro-optimization
// not worth the fragility at this table's realistic scale), and extended
// so each destination-prefix node carries a small list of source-specific
// entries (plus optionally an any-source one) instead of a single peer:
// destination specificity is resolved entirely by the trie walk (the
// node found is the single most specific destination prefix with any
// route at all, full stop -- a less specific destination's entries are
// never considered once a more specific one is found, even if only the
// less specific one's source would have matched); source specificity is
// only ever a tiebreaker among the handful of entries installed at that
// exact same destination prefix.
type RouteTable struct {
	mu   sync.RWMutex
	ipv4 *trieNode
	ipv6 *trieNode
}

// srcEntry is one (source-prefix, peer) pairing installed at a single,
// exact destination-trie node. An invalid (zero value) src means "any
// source".
type srcEntry struct {
	src  netip.Prefix
	peer *Peer
}

// trieNode is one node of the destination patricia trie. srcs is empty
// for a pure branch node that exists only to fork two more-specific
// prefixes apart, never installed as a route of its own.
type trieNode struct {
	srcs       []srcEntry
	child      [2]*trieNode
	parent     *trieNode
	parentBit  byte // which of parent.child this node occupies; meaningless if parent == nil
	cidr       uint8
	bitAtByte  uint8
	bitAtShift uint8
	bits       []byte // this node's own prefix bytes, masked to cidr bits
}

func NewRouteTable() *RouteTable {
	return &RouteTable{}
}

// commonBits returns how many leading bits a and b (equal-length byte
// slices) share.
func commonBits(a, b []byte) uint8 {
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return uint8(i)*8 + uint8(bits.LeadingZeros8(a[i]^b[i]))
		}
	}
	return uint8(len(a)) * 8
}

func (n *trieNode) choose(ip []byte) byte {
	return (ip[n.bitAtByte] >> n.bitAtShift) & 1
}

// maskSelf zeros every bit of n.bits beyond n.cidr, so two prefixes that
// agree on their first cidr bits always compare equal regardless of
// whatever garbage (or a longer, more specific caller's address) is
// sitting in the trailing bits.
func (n *trieNode) maskSelf() {
	cidr := int(n.cidr)
	for i := range n.bits {
		bitOffset := i * 8
		switch {
		case bitOffset >= cidr:
			n.bits[i] = 0
		case bitOffset+8 > cidr:
			keep := cidr - bitOffset
			n.bits[i] &= ^byte(0) << (8 - keep)
		}
	}
}

func newTrieNode(ip []byte, cidr uint8) *trieNode {
	n := &trieNode{
		bits:       append([]byte(nil), ip...),
		cidr:       cidr,
		bitAtByte:  cidr / 8,
		bitAtShift: 7 - cidr%8,
	}
	n.maskSelf()
	return n
}

// nodePlacement walks down from n looking for the node with exactly cidr
// bits on the path to ip. exact reports whether that exact node exists;
// parent is either that exact node, or (if !exact) the deepest existing
// node on the path from which a new (ip, cidr) node would need to branch.
func (n *trieNode) nodePlacement(ip []byte, cidr uint8) (parent *trieNode, exact bool) {
	for n != nil && n.cidr <= cidr && commonBits(n.bits, ip) >= n.cidr {
		parent = n
		if parent.cidr == cidr {
			exact = true
			return
		}
		n = n.child[n.choose(ip)]
	}
	return
}

// attach hooks node in as parent's child (by address-bit choice), or as
// the trie root if parent is nil.
func attach(root **trieNode, parent, node *trieNode) {
	if parent == nil {
		node.parent = nil
		*root = node
		return
	}
	bit := parent.choose(node.bits)
	node.parent = parent
	node.parentBit = bit
	parent.child[bit] = node
}

// insertDest finds or creates the trie node for the exact destination
// prefix (ip, cidr), creating whatever intermediate branch node is
// needed to fork it apart from any existing, differently-specific
// prefix already on its path.
func insertDest(root **trieNode, ip []byte, cidr uint8) *trieNode {
	if *root == nil {
		n := newTrieNode(ip, cidr)
		*root = n
		return n
	}
	parent, exact := (*root).nodePlacement(ip, cidr)
	if exact {
		return parent
	}

	newNode := newTrieNode(ip, cidr)

	var down *trieNode
	if parent == nil {
		down = *root
	} else {
		bit := parent.choose(ip)
		down = parent.child[bit]
		if down == nil {
			newNode.parent = parent
			newNode.parentBit = bit
			parent.child[bit] = newNode
			return newNode
		}
	}

	branchCidr := cidr
	if common := commonBits(down.bits, ip); common < branchCidr {
		branchCidr = common
	}

	if newNode.cidr == branchCidr {
		// newNode itself is the fork point: down becomes its child.
		bit := newNode.choose(down.bits)
		down.parent = newNode
		down.parentBit = bit
		newNode.child[bit] = down
		attach(root, parent, newNode)
		return newNode
	}

	branch := newTrieNode(newNode.bits, branchCidr)
	bit := branch.choose(down.bits)
	down.parent = branch
	down.parentBit = bit
	branch.child[bit] = down
	bit = branch.choose(newNode.bits)
	newNode.parent = branch
	newNode.parentBit = bit
	branch.child[bit] = newNode
	attach(root, parent, branch)
	return newNode
}

// removeNode compacts n out of the trie once it carries no routes of its
// own (len(n.srcs)==0): a node with two children is still needed as a
// fork point and is left in place, otherwise its one child (or nil)
// splices directly into n's old position, and n's former parent is
// recursively checked the same way, since removing n may have just left
// a synthetic branch node with only one child and no route of its own.
func removeNode(root **trieNode, n *trieNode) {
	if len(n.srcs) > 0 {
		return
	}
	if n.child[0] != nil && n.child[1] != nil {
		return
	}
	child := n.child[0]
	if child == nil {
		child = n.child[1]
	}
	if child != nil {
		child.parent = n.parent
		child.parentBit = n.parentBit
	}
	if n.parent == nil {
		*root = child
		return
	}
	n.parent.child[n.parentBit] = child
	removeNode(root, n.parent)
}

// lookupDest returns the deepest destination-trie node covering ip that
// carries at least one route, or nil if none does. This alone resolves
// destination specificity, before any source matching happens -- see
// RouteTable's doc comment.
func lookupDest(root *trieNode, ip []byte) *trieNode {
	var found *trieNode
	n := root
	size := uint8(len(ip))
	for n != nil && commonBits(n.bits, ip) >= n.cidr {
		if len(n.srcs) > 0 {
			found = n
		}
		if n.bitAtByte == size {
			break
		}
		n = n.child[n.choose(ip)]
	}
	return found
}

func (rt *RouteTable) rootFor(p netip.Prefix) **trieNode {
	if p.Addr().Is4() {
		return &rt.ipv4
	}
	return &rt.ipv6
}

// Set installs or replaces the route for (src, dst). src may be the zero
// netip.Prefix{} for an ordinary, non-source-specific route.
func (rt *RouteTable) Set(src, dst netip.Prefix, peer *Peer) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	node := insertDest(rt.rootFor(dst), dst.Addr().AsSlice(), uint8(dst.Bits()))
	for i := range node.srcs {
		if node.srcs[i].src == src {
			node.srcs[i].peer = peer
			return
		}
	}
	node.srcs = append(node.srcs, srcEntry{src: src, peer: peer})
}

// Remove deletes the route for (src, dst), if any.
func (rt *RouteTable) Remove(src, dst netip.Prefix) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	root := rt.rootFor(dst)
	node, exact := (*root).nodePlacement(dst.Addr().AsSlice(), uint8(dst.Bits()))
	if !exact {
		return
	}
	for i := range node.srcs {
		if node.srcs[i].src == src {
			node.srcs = append(node.srcs[:i], node.srcs[i+1:]...)
			removeNode(root, node)
			return
		}
	}
}

// RemovePeer deletes every route pointing at peer, e.g. when its session dies.
func (rt *RouteTable) RemovePeer(peer *Peer) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	removePeerFromTrie(&rt.ipv4, rt.ipv4, peer)
	removePeerFromTrie(&rt.ipv6, rt.ipv6, peer)
}

// removePeerFromTrie walks post-order (both children fully settled,
// including their own compaction, before n itself is considered) so that
// by the time n's turn comes, n.child[0]/n.child[1] are already in their
// final state and removeNode's upward climb from n never needs to
// revisit a subtree this walk hasn't finished with yet.
func removePeerFromTrie(root **trieNode, n *trieNode, peer *Peer) {
	if n == nil {
		return
	}
	removePeerFromTrie(root, n.child[0], peer)
	removePeerFromTrie(root, n.child[1], peer)
	kept := n.srcs[:0]
	changed := false
	for _, s := range n.srcs {
		if s.peer == peer {
			changed = true
			continue
		}
		kept = append(kept, s)
	}
	if changed {
		n.srcs = kept
		removeNode(root, n)
	}
}

// Debug returns a human-readable dump of every installed route, for
// diagnostics/tests — not meant for programmatic use.
func (rt *RouteTable) Debug() []string {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	var out []string
	var walk func(n *trieNode)
	walk = func(n *trieNode) {
		if n == nil {
			return
		}
		addr, _ := netip.AddrFromSlice(n.bits)
		dst := netip.PrefixFrom(addr, int(n.cidr))
		for _, s := range n.srcs {
			if s.src.IsValid() {
				out = append(out, fmt.Sprintf("%s from %s via %s", dst, s.src, s.peer.ID))
			} else {
				out = append(out, fmt.Sprintf("%s via %s", dst, s.peer.ID))
			}
		}
		walk(n.child[0])
		walk(n.child[1])
	}
	walk(rt.ipv4)
	walk(rt.ipv6)
	return out
}

// Lookup finds the peer that can carry traffic from src to dst, per
// draft-ietf-babel-source-specific's selection rule: the destination
// match is resolved first (longest destination prefix wins); only among
// entries tied on destination specificity does the source prefix act as a
// tiebreaker, so a source-specific entry is preferred over an any-source
// one at the same destination specificity, but never overrides a more
// specific destination match.
func (rt *RouteTable) Lookup(src, dst netip.Addr) (*Peer, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	var root *trieNode
	if dst.Is4() {
		root = rt.ipv4
	} else {
		root = rt.ipv6
	}
	node := lookupDest(root, dst.AsSlice())
	if node == nil {
		return nil, false
	}
	var best *srcEntry
	for i := range node.srcs {
		s := &node.srcs[i]
		if s.src.IsValid() && !s.src.Contains(src) {
			continue
		}
		if best == nil || srcBits(s.src) > srcBits(best.src) {
			best = s
		}
	}
	if best == nil {
		return nil, false
	}
	return best.peer, true
}

// srcBits treats "any source" as less specific than every real prefix,
// including /0, so it always loses a tie against a genuine source match.
func srcBits(p netip.Prefix) int {
	if !p.IsValid() {
		return -1
	}
	return p.Bits()
}
