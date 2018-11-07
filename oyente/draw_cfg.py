import graphviz as gv
import functools
from functools import reduce
from opcodes import stack_v
import pprint

def add_nodes(graph, nodes):
    for n in nodes:
        if isinstance(n, tuple):
            graph.node(n[0], **n[1])
        else:
            graph.node(n)
    return graph


def add_edges(graph, edges):
    for e in edges:
        if isinstance(e[0], tuple):
            graph.edge(*e[0], **e[1])
        else:
            graph.edge(*e)
    return graph

def create_graph(n, e, filename):
    digraph = functools.partial(gv.Digraph, format='svg')
    g = add_edges(add_nodes(digraph(), n), e)
    g.render(filename=filename, cleanup=True)
    return g

split_line = '\n' + '=' * 40 + '\n'

def make_label(block, show_constraints):
    label = """{}

line number : ({}, {})

{}

stack sum: {}
block gas: {}
       """.format(
               block.type,
               block.start, block.end,
               '\n'.join(block.instructions),
               block.stksum,
               block.gas)

    if block.acc_gas:
        label += '\naccumulated gas :\n{}\n'.format(
                pprint.pformat(block.acc_gas))

    if show_constraints:
        if block.gas_constraints:
            label += split_line + split_line.join(
                    ["gas_assignment{}:\n{}".format(i + 1, '\n'.join(v)) \
                            for i, v in enumerate(block.gas_constraints.values())])
        if block.path_cond:
            label += split_line + split_line.join(
                    ["path_constraints{}:\n{}".format(
                            i + 1, ',\n'.join(map(str, v)))
                                for i, v in enumerate(block.path_cond.values())])
    if block.source:
        label += split_line + block.source[-1].replace('\n', '\l')
        # label += split_line + split_line.join(block.source)
    else:
        label += split_line + 'no source available'
    return label

def cfg_nodes(blocks, lgp, show_constraints, src_map):
    nodes = [(str(block.start), \
             { 'label' : make_label(block, show_constraints), \
                'shape': 'box', \
                'style': 'filled', \
                'fillcolor': '' if block.visited else '#ffffff'
             }) for block in blocks]
    return nodes

def mark_long_node(path, nodes):
    for i, node in enumerate(nodes):
        if int(node[0]) in path:
            nodes[i][1]['fillcolor'] = '#f4f141'
    return nodes

def mark_weak_node(blocks, nodes):
    for i, (block, node) in \
            enumerate(zip(blocks, nodes)):
        if block.weakness:
            nodes[i][1]['fillcolor'] = '#f44242'
            nodes[i][1]['label'] = 'weakness: {}\n\n{}\n'.format(
                    str(block.weakness), nodes[i][1]['label'])
    return nodes

def draw_long_edge(path, edges):
    path_edges = list(zip(path[:-1], path[1:]))
    for i, edge in enumerate(edges):
        (b, e) = edge[0]
        b, e = int(b), int(e)
        if (b, e) in path_edges:
            edges[i][1]['color'] = 'red'
    return edges

def draw_weak_edge(blocks, paths, edges):
    weak_blocks = set(block.start \
            for block in blocks if block.weakness)
    weak_paths = [path for path in paths \
            if any([b in weak_blocks for b in path])]
    weak_edges = set()
    for path in weak_paths:
        path_edges = list(zip(path[:-1], path[1:]))
        for edge in path_edges:
            weak_edges.add(edge)

    for i, edge in enumerate(edges):
        (b, e) = edge[0]
        b, e = int(b), int(e)
        if (b, e) in weak_edges:
            edges[i][1]['color'] = 'red'
    return edges

def cfg_edges(edges, p_cond, show_cond):

    edges = [(b, e) for b in edges for e in edges[b]]

    return [((str(b), str(e)),
            {'label' : ('\n' + '=' * 40 + '\n').join(p_cond.get((b, e), [])) \
                    if show_cond else '',
             'color': 'blue'
            }) for (b, e) in edges]
