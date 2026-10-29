import ipaddress


class Node:
    def __init__(self, ip, threat_level, attack_type):
        address = ipaddress.IPv4Address(ip.strip())
        self.ip = str(address)
        self.key = int(address)
        self.threat_level = threat_level
        self.attack_type = attack_type
        self.hits = 1
        self.left = None
        self.right = None

    def as_dict(self):
        return {
            "ip": self.ip,
            "threat_level": self.threat_level,
            "attack_type": self.attack_type,
            "hits": self.hits,
        }


class ThreatTree:
    def __init__(self):
        self.root = None

    @staticmethod
    def to_key(ip):
        return int(ipaddress.IPv4Address(ip.strip()))

    def insert(self, ip, threat_level, attack_type):
        new_node = Node(ip, threat_level, attack_type)
        if self.root is None:
            self.root = new_node
            return new_node

        current = self.root
        while True:
            if new_node.key < current.key:
                if current.left is None:
                    current.left = new_node
                    return new_node
                current = current.left
            elif new_node.key > current.key:
                if current.right is None:
                    current.right = new_node
                    return new_node
                current = current.right
            else:
                current.hits += 1
                current.threat_level = max(current.threat_level, threat_level)
                current.attack_type = attack_type
                return current

    def search(self, ip):
        key = self.to_key(ip)
        current = self.root
        path = []
        while current is not None:
            path.append(current.ip)
            if key == current.key:
                return current, path
            current = current.left if key < current.key else current.right
        return None, path

    def delete(self, ip):
        key = self.to_key(ip)
        self.root, removed = self._delete(self.root, key)
        return removed

    def _delete(self, node, key):
        if node is None:
            return None, False
        if key < node.key:
            node.left, removed = self._delete(node.left, key)
            return node, removed
        if key > node.key:
            node.right, removed = self._delete(node.right, key)
            return node, removed

        if node.left is None:
            return node.right, True
        if node.right is None:
            return node.left, True

        successor = node.right
        while successor.left is not None:
            successor = successor.left

        node.ip = successor.ip
        node.key = successor.key
        node.threat_level = successor.threat_level
        node.attack_type = successor.attack_type
        node.hits = successor.hits
        node.right, _ = self._delete(node.right, successor.key)
        return node, True

    def in_order(self):
        result = []
        self._in_order(self.root, 1, result)
        return result

    def _in_order(self, node, level, result):
        if node is None:
            return
        self._in_order(node.left, level + 1, result)

        if level == 1:
            role = "Root"
        elif node.left is None and node.right is None:
            role = "Leaf"
        else:
            role = "Branch"

        record = node.as_dict()
        record["level"] = level
        record["role"] = role
        record["degree"] = (node.left is not None) + (node.right is not None)
        result.append(record)

        self._in_order(node.right, level + 1, result)

    def height(self):
        return self._height(self.root)

    def _height(self, node):
        if node is None:
            return 0
        return 1 + max(self._height(node.left), self._height(node.right))

    def stats(self):
        records = self.in_order()
        return {
            "weight": len(records),
            "height": self.height(),
            "leaves": sum(1 for r in records if r["role"] == "Leaf"),
            "branches": sum(1 for r in records if r["role"] == "Branch"),
            "critical": sum(1 for r in records if r["threat_level"] >= 8),
            "root": self.root.ip if self.root else None,
        }

    def to_dict(self):
        return self._serialize(self.root)

    def _serialize(self, node):
        if node is None:
            return None
        data = node.as_dict()
        data["left"] = self._serialize(node.left)
        data["right"] = self._serialize(node.right)
        return data
