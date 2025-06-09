import networkx as nx
import matplotlib.pyplot as plt

edges = [(1, 2, {'weight': 23, 'name': 'SSOP'}), (1, 3, {'weight': 1, 'name': 'amdar'}), (1, 4, {'weight': 36, 'name': 'demopy'}), (1, 5, {'weight': 3, 'name': 'rr'}), (1, 6, {'weight': 19, 'name': 'demoajax'}), (1, 7, {'weight': 2, 'name': 'NVODS'}), (1, 8, {'weight': 1, 'name': 'awspub'}), (1, 9, {'weight': 3, 'name': 'ints-mats'})]

nodemapping = {1: 'ALL', 2: 'SSOP', 3: 'AMDAR', 4: 'demopy', 5: 'RR', 6: 'demoajax', 7: 'NVODS', 8: 'awspub', 9: 'ints-mats'}

inner = []
np = int(0)
snp = int(0)
scale = int(50)
for b, e, a in edges:
    w = int(a['weight'])
    inner.append(w * scale)
    np = np + w
    snp = snp + (w * scale)
    nodemapping[e] = nodemapping[e] + ' (' + str(w) + ')'

nodemapping[1] = nodemapping[1] + ' (' + str(np) + ')'

nodesizes = []
nodesizes.append(int(snp))
for v in inner:
    nodesizes.append(int(v))

print("nodesizes: " + str(nodesizes))

G = nx.Graph(numc="Num connections")
G.add_edges_from(edges)
G = nx.relabel_nodes(G, nodemapping)
plot = nx.draw(G, with_labels=True, node_size = nodesizes)
plt.savefig('/usr/share/nginx/html/static/graphs/cbp.png')

