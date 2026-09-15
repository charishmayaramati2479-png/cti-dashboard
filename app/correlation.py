import networkx as nx
from collections import defaultdict


def build_correlation_graph(iocs, max_nodes=300):
    """
    Build a graph linking IOCs that share:
      - malware_family
      - source
      - ioc_type

    Returns {'nodes': [...], 'edges': [...]} JSON-friendly.
    """
    G = nx.Graph()

    # Attribute nodes
    family_groups = defaultdict(list)
    for ioc in iocs[:max_nodes]:
        node_id = f"ioc:{ioc.id}"
        G.add_node(node_id, label=ioc.value, kind="ioc",
                   ioc_type=ioc.ioc_type, source=ioc.source,
                   risk=ioc.risk_score, anomaly=bool(ioc.anomaly))

        if ioc.malware_family:
            fam_id = f"family:{ioc.malware_family}"
            G.add_node(fam_id, label=ioc.malware_family, kind="family")
            G.add_edge(node_id, fam_id, kind="malware_family")
            family_groups[ioc.malware_family].append(node_id)

        src_id = f"source:{ioc.source}"
        G.add_node(src_id, label=ioc.source, kind="source")
        G.add_edge(node_id, src_id, kind="source")

    # Cross-link IOCs sharing a malware family
    for family, members in family_groups.items():
        for i in range(len(members)):
            for j in range(i + 1, min(i + 4, len(members))):
                G.add_edge(members[i], members[j], kind="shared_family")

    nodes = [
        {
            "id": n,
            "label": d.get("label", n),
            "kind": d.get("kind", "unknown"),
            "risk": d.get("risk", 0),
            "anomaly": d.get("anomaly", False),
            "source": d.get("source", ""),
            "ioc_type": d.get("ioc_type", "")
        }
        for n, d in G.nodes(data=True)
    ]
    edges = [{"from": u, "to": v, "kind": d.get("kind", "")}
             for u, v, d in G.edges(data=True)]

    return {"nodes": nodes, "edges": edges,
            "stats": {"node_count": len(nodes), "edge_count": len(edges)}}