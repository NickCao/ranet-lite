// Package sadr implements source-address-dependent routing tables.
package sadr

import (
	"math/bits"
	"net/netip"
	"sync"
)

// Table maps source and destination prefix pairs to values. Lookup resolves
// the longest matching destination first, then the longest matching source
// only among entries at that destination prefix.
type Table[V comparable] struct {
	mu   sync.RWMutex
	ipv4 *trieNode[V]
	ipv6 *trieNode[V]
}

type srcEntry[V comparable] struct {
	src   netip.Prefix
	value V
}

type trieNode[V comparable] struct {
	srcs       []srcEntry[V]
	child      [2]*trieNode[V]
	parent     *trieNode[V]
	parentBit  byte
	cidr       uint8
	bitAtByte  uint8
	bitAtShift uint8
	bits       []byte
}

func commonBits(a, b []byte) uint8 {
	for i := range a {
		if a[i] != b[i] {
			return uint8(i)*8 + uint8(bits.LeadingZeros8(a[i]^b[i]))
		}
	}
	return uint8(len(a)) * 8
}

func (n *trieNode[V]) choose(ip []byte) byte {
	return (ip[n.bitAtByte] >> n.bitAtShift) & 1
}

func newTrieNode[V comparable](ip []byte, cidr uint8) *trieNode[V] {
	n := &trieNode[V]{
		bits:       append([]byte(nil), ip...),
		cidr:       cidr,
		bitAtByte:  cidr / 8,
		bitAtShift: 7 - cidr%8,
	}
	for i := range n.bits {
		bitOffset := i * 8
		switch {
		case bitOffset >= int(cidr):
			n.bits[i] = 0
		case bitOffset+8 > int(cidr):
			n.bits[i] &= ^byte(0) << (8 - (int(cidr) - bitOffset))
		}
	}
	return n
}

func (n *trieNode[V]) nodePlacement(ip []byte, cidr uint8) (parent *trieNode[V], exact bool) {
	for n != nil && n.cidr <= cidr && commonBits(n.bits, ip) >= n.cidr {
		parent = n
		if parent.cidr == cidr {
			return parent, true
		}
		n = n.child[n.choose(ip)]
	}
	return parent, false
}

func attach[V comparable](root **trieNode[V], parent, node *trieNode[V]) {
	if parent == nil {
		node.parent = nil
		*root = node
		return
	}
	bit := parent.choose(node.bits)
	node.parent, node.parentBit = parent, bit
	parent.child[bit] = node
}

func insertDest[V comparable](root **trieNode[V], ip []byte, cidr uint8) *trieNode[V] {
	if *root == nil {
		*root = newTrieNode[V](ip, cidr)
		return *root
	}
	parent, exact := (*root).nodePlacement(ip, cidr)
	if exact {
		return parent
	}
	newNode := newTrieNode[V](ip, cidr)
	var down *trieNode[V]
	if parent == nil {
		down = *root
	} else {
		bit := parent.choose(ip)
		down = parent.child[bit]
		if down == nil {
			newNode.parent, newNode.parentBit = parent, bit
			parent.child[bit] = newNode
			return newNode
		}
	}
	branchCidr := cidr
	if common := commonBits(down.bits, ip); common < branchCidr {
		branchCidr = common
	}
	if newNode.cidr == branchCidr {
		bit := newNode.choose(down.bits)
		down.parent, down.parentBit = newNode, bit
		newNode.child[bit] = down
		attach(root, parent, newNode)
		return newNode
	}
	branch := newTrieNode[V](newNode.bits, branchCidr)
	bit := branch.choose(down.bits)
	down.parent, down.parentBit = branch, bit
	branch.child[bit] = down
	bit = branch.choose(newNode.bits)
	newNode.parent, newNode.parentBit = branch, bit
	branch.child[bit] = newNode
	attach(root, parent, branch)
	return newNode
}

func removeNode[V comparable](root **trieNode[V], n *trieNode[V]) {
	if len(n.srcs) > 0 || (n.child[0] != nil && n.child[1] != nil) {
		return
	}
	child := n.child[0]
	if child == nil {
		child = n.child[1]
	}
	if child != nil {
		child.parent, child.parentBit = n.parent, n.parentBit
	}
	if n.parent == nil {
		*root = child
		return
	}
	n.parent.child[n.parentBit] = child
	removeNode(root, n.parent)
}

func lookupDest[V comparable](root *trieNode[V], ip []byte) *trieNode[V] {
	var found *trieNode[V]
	for n := root; n != nil && commonBits(n.bits, ip) >= n.cidr; n = n.child[n.choose(ip)] {
		if len(n.srcs) > 0 {
			found = n
		}
		if n.bitAtByte == uint8(len(ip)) {
			break
		}
	}
	return found
}

func (t *Table[V]) rootFor(p netip.Prefix) **trieNode[V] {
	if p.Addr().Is4() {
		return &t.ipv4
	}
	return &t.ipv6
}

// Set installs or replaces the value for (src, dst). An invalid src matches
// every source address.
func (t *Table[V]) Set(src, dst netip.Prefix, value V) {
	t.mu.Lock()
	defer t.mu.Unlock()
	node := insertDest(t.rootFor(dst), dst.Addr().AsSlice(), uint8(dst.Bits()))
	for i := range node.srcs {
		if node.srcs[i].src == src {
			node.srcs[i].value = value
			return
		}
	}
	node.srcs = append(node.srcs, srcEntry[V]{src: src, value: value})
}

// Remove deletes the value for (src, dst), if present.
func (t *Table[V]) Remove(src, dst netip.Prefix) {
	t.mu.Lock()
	defer t.mu.Unlock()
	root := t.rootFor(dst)
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

// RemoveValue deletes every route whose value equals value.
func (t *Table[V]) RemoveValue(value V) {
	t.mu.Lock()
	defer t.mu.Unlock()
	removeValueFromTrie(&t.ipv4, t.ipv4, value)
	removeValueFromTrie(&t.ipv6, t.ipv6, value)
}

func removeValueFromTrie[V comparable](root **trieNode[V], n *trieNode[V], value V) {
	if n == nil {
		return
	}
	removeValueFromTrie(root, n.child[0], value)
	removeValueFromTrie(root, n.child[1], value)
	kept := n.srcs[:0]
	changed := false
	for _, entry := range n.srcs {
		if entry.value == value {
			changed = true
			continue
		}
		kept = append(kept, entry)
	}
	if changed {
		n.srcs = kept
		removeNode(root, n)
	}
}

// Lookup returns the value for traffic from src to dst.
func (t *Table[V]) Lookup(src, dst netip.Addr) (V, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var zero V
	root := t.ipv6
	if dst.Is4() {
		root = t.ipv4
	}
	node := lookupDest(root, dst.AsSlice())
	if node == nil {
		return zero, false
	}
	var best *srcEntry[V]
	for i := range node.srcs {
		entry := &node.srcs[i]
		if entry.src.IsValid() && !entry.src.Contains(src) {
			continue
		}
		if best == nil || sourceBits(entry.src) > sourceBits(best.src) {
			best = entry
		}
	}
	if best == nil {
		return zero, false
	}
	return best.value, true
}

func sourceBits(p netip.Prefix) int {
	if !p.IsValid() {
		return -1
	}
	return p.Bits()
}
